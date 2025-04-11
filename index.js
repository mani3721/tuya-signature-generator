const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

app.get('/generate-signature', (req, res) => {
  const clientId = req.headers['client_id'];
  const clientSecret = req.headers['secret'];

  if (!clientId || !clientSecret) {
    return res.status(400).json({ error: 'Missing client_id or secret in headers' });
  }

  const t = Date.now().toString();
  const signStr = clientId + t;

  const sign = crypto
    .createHmac('sha256', clientSecret)
    .update(signStr)
    .digest('hex')
    .toUpperCase();

  res.json({
    client_id: clientId,
    t,
    sign,
    sign_method: 'HMAC-SHA256'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signature server running at http://localhost:${PORT}`);
});
