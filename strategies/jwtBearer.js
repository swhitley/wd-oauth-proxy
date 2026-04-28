'use strict';

const crypto = require('crypto');
const { IAMCredentialsClient } = require('@google-cloud/iam-credentials');

let _iamClient = null;
function getIamClient() {
  if (!_iamClient) _iamClient = new IAMCredentialsClient();
  return _iamClient;
}

async function fetchToken({ targetUrl, clientId, scope, httpClient }) {
  const iamClient = getIamClient();
  const iat = Math.floor(Date.now() / 1000);
  
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: targetUrl,
    iat,
    exp: iat + 300, 
    jti: crypto.randomUUID()
  };

  if (scope) payload.scope = scope;

  // Use GCP Service Account to sign the JWT, keeping private keys out of proxy memory
  const [response] = await iamClient.signJwt({
    name: `projects/-/serviceAccounts/${clientId}`,
    payload: JSON.stringify(payload),
  });

  const tokenResponse = await httpClient.post(
    targetUrl,
    new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: response.signedJwt,
    }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  return tokenResponse.data;
}

module.exports = { fetchToken };