'use strict';

async function fetchToken({ targetUrl, clientId, clientSecret, scope, httpClient }) {
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret
  });

  if (scope) params.append('scope', scope);

  const response = await httpClient.post(targetUrl, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  return response.data;
}

module.exports = { fetchToken };