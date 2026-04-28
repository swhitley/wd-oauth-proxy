'use strict';

async function fetchToken({ targetUrl, clientId, clientSecret, scope, httpClient }) {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    ...(scope ? { scope } : {}),
  });

  const response = await httpClient.post(targetUrl, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  return response.data;
}

module.exports = { fetchToken };