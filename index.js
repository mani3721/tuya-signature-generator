const express = require('express');
const qs = require('qs');
const crypto = require('crypto');
const cors = require('cors');
const axios = require('axios'); // You need axios for making HTTP requests

const app = express();
app.use(cors());
app.use(express.json());

// Create an axios instance for making requests
const httpClient = axios.create({
  baseURL: 'https://openapi.tuyain.com' // Replace with your actual API base URL
});

app.get('/sign-token', async (req, res) => {
  try {
    const { client_id, secret } = req.headers;
    
    if (!client_id || !secret) {
      return res.status(400).json({ error: 'Missing client_id or secret in headers' });
    }

    const method = 'GET';
    const timestamp = Date.now().toString();
    const signUrl = '/v1.0/token?grant_type=1';
    const contentHash = crypto.createHash('sha256').update('').digest('hex');
    const stringToSign = [method, contentHash, '', signUrl].join('\n');
    const signStr = client_id + timestamp + stringToSign;

    const sign = encryptStr(signStr, secret);

    const headers = {
      t: timestamp,
      sign_method: 'HMAC-SHA256',
      client_id: client_id,
      sign: sign
    };

    // Make the request to get the token
    const response = await httpClient.get('/v1.0/token?grant_type=1', { headers });

    // Return the response data along with the signing information
    res.json({
      ...(response.data.result || {}),
      client_id,
      t: timestamp,
      sign,
      sign_method: 'HMAC-SHA256'
    });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'Failed to get token', message: error.message });
  }
});

// Fixed function declaration - removed async and =>
function encryptStr(str, secret) {
  return crypto.createHmac('sha256', secret).update(str, 'utf8').digest('hex').toUpperCase();
}


app.get('/getRequestSign', async (req, res) => {


  try {

    const { client_id, secret, access_token, path, method = 'GET' } = req.headers;
    if (!client_id || !secret || !access_token || !path) {
      return res.status(400).json({ 
        error: 'Missing required parameters', 
        message: 'client_id, secret, access_token, and path are required in headers' 
      });
    }

    const query = req.query || {};
    const body = req.body || {};

    const t = Date.now().toString();
    const [uri, pathQuery] = path.split('?');
    
    const queryFromPath = pathQuery ? qs.parse(pathQuery) : {};
    const queryMerged = { ...queryFromPath, ...query };
    
    const sortedQuery = {};
    Object.keys(queryMerged)
      .sort()
      .forEach((i) => (sortedQuery[i] = queryMerged[i]));
  
    const querystring = decodeURIComponent(qs.stringify(sortedQuery));
    const url = querystring ? `${uri}?${querystring}` : uri;
    const contentHash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    const stringToSign = [method, contentHash, '', url].join('\n');
    const signStr = client_id + access_token + t + stringToSign;

    const signedHeaders = {
      t,
      path: url,
      client_id,
      sign: encryptStr(signStr, secret),
      sign_method: 'HMAC-SHA256',
      access_token: access_token,
    };

    res.status(200).json(signedHeaders);

  } catch (error) {
    console.error("Error generating signature:", error);
    res.status(500).json({ error: 'Failed to generate signature', message: error.message });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signature server running at http://localhost:${PORT}`);
});
