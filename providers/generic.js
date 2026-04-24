'use strict';

/**
 * providers/generic.js
 *
 * Generic OAuth 2.0 provider using the client_credentials grant type.
 * Default handler when no named provider matches the incoming request.
 *
 * The clientId and clientSecret passed to fetchToken() are always sourced
 * from Secret Manager by index.js — they are never supplied by the caller.
 */

const axios = require('axios');

const meta = {
  id:          'generic',
  description: 'Generic OAuth 2.0 client_credentials flow.',
  implemented: true,
};

/**
 * Fetches an access token from an arbitrary OAuth 2.0 token endpoint.
 *
 * @param {object} params
 * @param {string}  params.targetUrl         Token endpoint URL.
 * @param {string}  params.clientId          Downstream client_id (from Secret Manager).
 * @param {string}  params.clientSecret      Downstream client_secret (from Secret Manager).
 * @param {string}  [params.scope]           Scope forwarded from the origin request.
 * @param {object}  [params.extraBodyFields] Additional form fields to include.
 * @returns {Promise<object>} Parsed token response JSON.
 */
async function fetchToken({
  targetUrl,
  clientId,
  clientSecret,
  scope,
  extraBodyFields = {},
}) {
  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     clientId,
    client_secret: clientSecret,
    ...(scope ? { scope } : {}),
    ...extraBodyFields,
  });

  // Allow the axios error to propagate — index.js handles it and passes the
  // vendor's HTTP status and body through verbatim to the caller.
  const response = await axios.post(targetUrl, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  return response.data;
}

module.exports = { meta, fetchToken };
