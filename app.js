const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const {authenticate} = require('@google-cloud/local-auth');
const {google} = require('googleapis');

const app = express();
const port = 8080;

// If modifying these scopes, delete token.json.
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
// The file token.json stores the user's access and refresh tokens, and is
// created automatically when the authorization flow completes for the first
// time.
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

/**
 * Reads previously authorized credentials from the save file.
 *
 * @return {Promise<OAuth2Client|null>}
 */
async function loadSavedCredentialsIfExist() {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content);
    return google.auth.fromJSON(credentials);
  } catch (err) {
    return null;
  }
}

/**
 * Serializes credentials to a file compatible with GoogleAuth.fromJSON.
 *
 * @param {OAuth2Client} client
 * @return {Promise<void>}
 */
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

/**
 * Load or request or authorization to call APIs.
 *
 */
async function authorize() {
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    return client;
  }
  client = await authenticate({
    scopes: SCOPES,
    keyfilePath: CREDENTIALS_PATH,
  });
  if (client.credentials) {
    await saveCredentials(client);
  }
  return client;
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
      console.error('Error in listMessages:', error);
      throw error;
    }
}

app.get('/emails', async (req, res) => {
    try {
        const auth = await authorize();
        const messages = await listMessages(auth, 15);
        
        let html = '<h1>Your Emails</h1>';
        html += '<style>body { font-family: sans-serif; } .email { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px; } .from, .subject { font-weight: bold; } .body { margin-top: 10px; white-space: pre-wrap; } </style>';
        
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
  console.log(`Access your emails at http://localhost:${port}/emails`);
}); 