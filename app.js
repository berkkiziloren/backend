require('dotenv').config();
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const { google } = require('googleapis');
const AWS = require('aws-sdk');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 8080;

const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

// AWS S3 setup
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});
const s3 = new AWS.S3();
const BUCKET_NAME = process.env.S3_BUCKET_NAME || 'YOUR_BUCKET_NAME'; // Set your bucket name here or via env
console.log(BUCKET_NAME);

// MongoDB setup
const MONGO_URI = process.env.MONGO_URI || 'YOUR_MONGODB_URI';
console.log(MONGO_URI);
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  // add other fields as needed
});
const User = mongoose.model('User', userSchema);

// Helper functions for S3 token storage
async function uploadTokenToS3(userId, tokenData) {
  const params = {
    Bucket: BUCKET_NAME,
    Key: `tokens/${userId}.json`,
    Body: JSON.stringify(tokenData),
    ContentType: 'application/json',
  };
  await s3.putObject(params).promise();
}

async function getTokenFromS3(userId) {
  try {
    const params = {
      Bucket: BUCKET_NAME,
      Key: `tokens/${userId}.json`,
    };
    const data = await s3.getObject(params).promise();
    return JSON.parse(data.Body.toString());
  } catch (err) {
    if (err.code === 'NoSuchKey') return null;
    throw err;
  }
}


async function loadSavedCredentialsIfExist(userId) {
  try {
    const credentials = await getTokenFromS3(userId);
    return google.auth.fromJSON(credentials);
  } catch (err) {
    return null;
  }
}

async function saveCredentials(userId, client) {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content);
  const key = keys.installed || keys.web;
  const payload = {
    type: 'authorized_user',
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: client.credentials.refresh_token,
    ...client.credentials,
  };
  await uploadTokenToS3(userId, payload);
}

async function listMessages(auth, maxResults = 10) {
  try {
    const gmail = google.gmail({ version: 'v1', auth });
    const res = await gmail.users.messages.list({
      userId: 'me',
      maxResults,
      q: 'in:inbox'
    });

    const messages = res.data.messages || [];
    if (messages.length === 0) {
      return [];
    }

    const messageDetails = await Promise.all(messages.map(async (message) => {
      try {
        const msg = await gmail.users.messages.get({
          userId: 'me',
          id: message.id,
          format: 'full',
        });

        const messageData = msg.data;

        const getBody = (message) => {
          let body = '';
          if (message.payload.parts) {
            const findBody = (parts) => {
              for (const part of parts) {
                if (part.parts) {
                  const result = findBody(part.parts);
                  if (result) return result;
                }
                if (part.mimeType === 'text/plain') {
                  return Buffer.from(part.body.data, 'base64').toString('utf-8');
                } else if (part.mimeType === 'text/html') {
                  return Buffer.from(part.body.data, 'base64').toString('utf-8');
                }
              }
              return null;
            };
            body = findBody(message.payload.parts) || '';
          } else if (message.payload.body.data) {
            body = Buffer.from(message.payload.body.data, 'base64').toString('utf-8');
          }
          return body;
        };

        messageData.body = getBody(messageData);

        const headers = messageData.payload.headers || [];
        messageData.headers = headers.reduce((acc, header) => {
          acc[header.name.toLowerCase()] = header.value;
          return acc;
        }, {});

        return messageData;
      } catch (err) {
        console.error(`Error fetching message ${message.id}:`, err.message);
        return null;
      }
    }));

    return messageDetails.filter(msg => msg !== null);
  } catch (error) {
    if (error.response && error.response.status === 401) {
      await fs.unlink(TOKEN_PATH).catch(err => console.error('Error deleting token file:', err));
    }
    console.error('Error in listMessages:', error);
    throw error;
  }
}

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(409).json({ error: 'User already exists' });
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashed });
  await user.save();
  res.json({ message: 'User registered' });
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// Auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/start-auth', requireAuth, async (req, res) => {
  try {
    const content = await fs.readFile(CREDENTIALS_PATH);
    const keys = JSON.parse(content);
    const key = keys.installed || keys.web;
    const oAuth2Client = new google.auth.OAuth2(
      key.client_id,
      key.client_secret,
      `http://${process.env.ENVIRONMENT === 'local' ? 'localhost' : 'http://backend-env.eba-xbmpiwm3.us-east-1.elasticbeanstalk.com/'}:${port}/oauth2callback`
    );

    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: SCOPES,
      state: req.user.userId,
      prompt: 'consent',
      include_granted_scopes: true
    });
    res.send(authorizeUrl);
  } catch (e) {
    console.error('Failed to start auth:', e);
    res.status(500).send('Failed to start authentication.');
  }
});

app.get('/oauth2callback', async (req, res) => {
  try {
    const code = req.query.code;
    const userId = req.query.state;
    const content = await fs.readFile(CREDENTIALS_PATH);
    const keys = JSON.parse(content);
    const key = keys.installed || keys.web;
    const oAuth2Client = new google.auth.OAuth2(
      key.client_id,
      key.client_secret,
      `http://localhost:${port}/oauth2callback`
    );

    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const payload = {
      type: 'authorized_user',
      client_id: key.client_id,
      client_secret: key.client_secret,
      refresh_token: tokens.refresh_token,
      ...tokens,
    };
    await uploadTokenToS3(userId, payload);
    res.send('<script>window.close();</script>');
  } catch (e) {
    console.error('Failed to get token:', e);
    res.status(500).send('Failed to get token.');
  }
});

app.get('/emails', requireAuth, async (req, res) => {
  try {
    console.log('JWT userId:', req.user.userId);
    const auth = await loadSavedCredentialsIfExist(req.user.userId);
    console.log('auth:', auth);
    if (!auth) {
      return res.status(401).send('You are not authenticated.');
    }
    const messages = await listMessages(auth, 15);
    let html = '';
    messages.forEach(msg => {
      html += '<div class="email">';
      html += `<div class="from">From: ${msg.headers.from || 'N/A'}</div>`;
      html += `<div class="subject">Subject: ${msg.headers.subject || 'No Subject'}</div>`;
      html += `<div class="date">Date: ${msg.headers.date || 'N/A'}</div>`;
      html += `<div class="body">${msg.body || 'No content'}</div>`;
      html += '</div>';
    });
    res.send(html);
  } catch (error) {
    console.error('Failed to get emails:', error);
    res.status(500).send('Failed to retrieve emails.');
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
}); 