'use strict';

/**
 * providers/google.js
 * * Implements Google's keyless JWT-based service-account flow.
 * Uses the IAM Credentials API to sign a JWT using the service account's 
 * identity without needing a physical private key file (.json).
 */

const { IAMCredentialsClient } = require('@google-cloud/iam-credentials');
const axios = require('axios');

const meta = {
  id:          'google',
  description: 'Google OAuth 2.0 using IAM Credentials keyless JWT signing.',
  implemented: true,
};

// Singleton client for IAM Credentials
let _iamClient = null;
function getIamClient() {
  if (!_iamClient) {
    _iamClient = new IAMCredentialsClient();
  }
  return _iamClient;
}

/**
 * Fetches a Google access token via the keyless JWT flow.
 *
 * @param {object} params
 * @param {string} params.clientId     Service account email (from Secret Manager).
 * @param {string} params.clientSecret OAuth scope(s) or Audience (from Secret Manager).
 * @param {string} [params.scope]      Scope override forwarded from the origin request.
 * @returns {Promise<object>} Token response.
 */
async function fetchToken({ clientId, clientSecret, scope }) {
  const iamClient = getIamClient();
  const serviceAccount = clientId; // The SA email stored in TARGET_X_CLIENT_ID
  const effectiveScope = scope || clientSecret; // Default scope stored in TARGET_X_CLIENT_SECRET

  console.log(`[Provider: google] Generating signed JWT for: ${serviceAccount}`);

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  // 1. Construct the JWT Payload
  // Note: Google's OAuth2 endpoint expects 'scope' for Access Tokens 
  // or 'target_audience' for ID Tokens. Here we assume Access Tokens.
  const payload = JSON.stringify({
    iss: serviceAccount,
    sub: serviceAccount,
    aud: 'https://oauth2.googleapis.com/token',
    iat,
    exp,
    scope: effectiveScope,
  });

  try {
    // 2. Sign the JWT using GCP IAM (Requires 'Service Account Token Creator' role)
    const [response] = await iamClient.signJwt({
      name: `projects/-/serviceAccounts/${serviceAccount}`,
      payload,
    });

    const { signedJwt } = response;

    // 3. Exchange the signed JWT for an access token
    const tokenResponse = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion:  signedJwt,
      }).toString(),
      { 
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' } 
      }
    );

    console.log(`[Provider: google] Successfully rotated token for ${serviceAccount}`);
    return tokenResponse.data;

  } catch (err) {
    const detail = err.response?.data?.error_description || err.message;
    console.error(`[Provider: google] Token fetch failed: ${detail}`);
    throw new Error(`Google OAuth failed: ${detail}`);
  }
}

module.exports = { meta, fetchToken };