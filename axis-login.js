const axios = require('axios');
const { JWE, JWK, JWS, util } = require('node-jose');

// Define the data to be encoded
const dataToEncode = {
  Data: {
    userName: 'alwebuser',
    password: 'acid_qa',
  },
  Risks: {},
};

const privateKeyPem = `-----BEGIN PRIVATE KEY-----
// Your private key here
-----END PRIVATE KEY-----`;

async function run() {
  try {
    // Create JWE
    const keystore = JWK.createKeyStore();
    const privateKey = await keystore.add(privateKeyPem, 'pem', { kid: 'key-id' });
    const jwe = await JWE.createEncrypt({ format: 'compact' }, privateKey)
      .update(JSON.stringify(dataToEncode))
      .final();

    // Create JWS
    const key = await JWK.asKey(privateKey);
    const jws = await JWS.createSign({ fields: { alg: 'RS256' } }, key)
      .update(jwe)
      .final();

    const encodedToken = await JWS.compact(jws);

    // Make HTTP request
    const url = 'https://sakshamuat.axisbank.co.in/gateway/api/v2/CRMNext/login';
    const headers = {
      'Content-Type': 'application/json',
      // Add any other required headers here
    };

    const response = await axios.post(url, encodedToken, { headers });

    console.log('API Response:', response.data);
  } catch (error) {
    console.error('Error:', error.message);
  }
}

run();
