const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const {google} = require('googleapis');

const app = express();
const port = 8080;

const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

async function loadSavedCredentialsIfExist() {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content);
    return google.auth.fromJSON(credentials);
  } catch (err) {
    return null;
  }
}

async function saveCredentials(client) {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content);
  const key = keys.installed || keys.web;
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/start-auth', async (req, res) => {
    try {
        const content = await fs.readFile(CREDENTIALS_PATH);
        const keys = JSON.parse(content);
        const key = keys.installed || keys.web;
        const oAuth2Client = new google.auth.OAuth2(
            key.client_id,
            key.client_secret,
            `http://localhost:${port}/oauth2callback`
        );

        const authorizeUrl = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
        });
        res.redirect(authorizeUrl);
    } catch (e) {
        console.error('Failed to start auth:', e);
        res.status(500).send('Failed to start authentication.');
    }
});

app.get('/oauth2callback', async (req, res) => {
    try {
        const code = req.query.code;
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

        const payload = JSON.stringify({
            type: 'authorized_user',
            client_id: key.client_id,
            client_secret: key.client_secret,
            refresh_token: tokens.refresh_token,
            ...tokens,
        });
        await fs.writeFile(TOKEN_PATH, payload);
        
        res.send('<script>window.close();</script>');
    } catch (e) {
        console.error('Failed to get token:', e);
        res.status(500).send('Failed to get token.');
    }
});

app.get('/emails', async (req, res) => {
    try {
        const auth = await loadSavedCredentialsIfExist();
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