const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/generate-signature', (req, res) => {
  const { client_id, secret } = req.headers;

  if (!client_id || !secret) {
    return res.status(400).json({ error: 'Missing client_id or secret in headers' });
  }

  const timestamp = new Date().getTime(); // Get current UTC timestamp in ms
  const signStr = client_id + timestamp;

  const sign = crypto
    .createHmac('sha256', secret)
    .update(signStr)
    .digest('hex')
    .toUpperCase();

  res.json({
    client_id,
    t: timestamp,
    sign,
    sign_method: 'HMAC-SHA256'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signature server running at http://localhost:${PORT}`);
});
