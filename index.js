import express from 'express';
import * as qs from 'qs';
import * as crypto from 'crypto';
import { default as axios } from 'axios';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

const config = {
  /* openapi host */
  host: 'https://openapi.tuyain.com',
};

const httpClient = axios.create({
  baseURL: config.host,
  timeout: 5 * 1e3,
});

/**
 * fetch highway login token
 */
async function getToken(clientId, secretKey) {
  const method = 'GET';
  const timestamp = Date.now().toString();
  const signUrl = '/v1.0/token?grant_type=1';
  const contentHash = crypto.createHash('sha256').update('').digest('hex');
  const stringToSign = [method, contentHash, '', signUrl].join('\n');
  const signStr = clientId + timestamp + stringToSign;

  const headers = {
    t: timestamp,
    sign_method: 'HMAC-SHA256',
    client_id: clientId,
    sign: await encryptStr(signStr, secretKey),
  };
  
  try {
    const { data: login } = await httpClient.get('/v1.0/token?grant_type=1', { headers });
    if (!login || !login.success) {
      throw Error(`fetch failed: ${login.msg}`);
    }
    return login.result.access_token;
  } catch (error) {
    throw Error(`Token fetch error: ${error.message}`);
  }
}

/**
 * fetch highway business data
 */
async function getDeviceInfo(accessToken, clientId, secretKey, path) {
  const query = {};
  const method = 'GET';
  const url = path;
  const reqHeaders = await getRequestSign(url, method, {}, query, {}, accessToken, clientId, secretKey);

  try {
    const { data } = await httpClient.request({
      method,
      data: {},
      params: {},
      headers: reqHeaders,
      url: reqHeaders.path,
    });
    
    if (!data || !data.success) {
      throw Error(`request api failed: ${data.msg}`);
    }
    
    return data.result;
  } catch (error) {
    throw Error(`Device info fetch error: ${error.message}`);
  }
}


/**
 * HMAC-SHA256 crypto function
 */
async function encryptStr(str, secret) {
  return crypto.createHmac('sha256', secret).update(str, 'utf8').digest('hex').toUpperCase();
}

/**
 * request sign, save headers 
 */
async function getRequestSign(
  path,
  method,
  headers = {},
  query = {},
  body = {},
  accessToken,
  clientId,
  secretKey
) {
  const t = Date.now().toString();
  const [uri, pathQuery] = path.split('?');
  const queryMerged = Object.assign(query, qs.parse(pathQuery));
  const sortedQuery = {};
  Object.keys(queryMerged)
    .sort()
    .forEach((i) => (sortedQuery[i] = query[i]));

  const querystring = decodeURIComponent(qs.stringify(sortedQuery));
  const url = querystring ? `${uri}?${querystring}` : uri;
  const contentHash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
  const stringToSign = [method, contentHash, '', url].join('\n');
  const signStr = clientId + accessToken + t + stringToSign;
  
  return {
    t,
    path: url,
    client_id: clientId,
    sign: await encryptStr(signStr, secretKey),
    sign_method: 'HMAC-SHA256',
    access_token: accessToken,
  };
}

// API endpoint to get device info
app.get('/get-device-info', async (req, res) => {
  // Read from query parameters instead of headers for better API design
  const { client_id, secret, path } = req.headers;
  
  if (!client_id || !secret || !path) {
    return res.status(400).json({
      success: false,
      message: 'Missing required parameters: client_id, secret, or path URL'
    });
  }
  
  try {
    // Get token from Tuya API
    const accessToken = await getToken(client_id, secret);
    
    // Get device info using the token
    const deviceInfo = await getDeviceInfo(accessToken, client_id, secret, path);
    
    // Return success response with device info
    res.status(200).json(deviceInfo);

  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signature server running at http://localhost:${PORT}`);
});
