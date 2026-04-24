'use strict';

/**
 * index.js — OAuth Proxy Cloud Function
 *
 * Acts as a proxy for OAuth token requests when vendors do not conform to
 * the credential format expected by Workday's External CredStore.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * How it works
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. Workday's CredStore calls POST /token using its standard client_credentials
 *     flow, presenting only the proxy's own client_id and client_secret.
 *  2. The proxy validates those credentials against Secret Manager.
 *  3. The proxy looks up the downstream vendor's client_id and client_secret
 *     from Secret Manager using target_id as a key — Workday never sees or
 *     stores downstream credentials.
 *  4. The proxy forwards the token request to the vendor's endpoint (target_url)
 *     and returns the response verbatim to Workday.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Request format  POST /token
 * ─────────────────────────────────────────────────────────────────────────────
 * Query parameters:
 *   target_url  {string}  Required. Token endpoint of the downstream OAuth server.
 *   target_id   {string}  Required. Key used to look up downstream credentials in
 *                         Secret Manager (see secretManager.js for naming rules).
 *   provider    {string}  Optional. Named OAuth provider module (default: "generic").
 *
 * Authentication (Workday sends one of these — Basic Auth is preferred):
 *   Basic Auth header:  Authorization: Basic base64(<proxy_client_id>:<proxy_client_secret>)
 *   Body params:        client_id=<proxy_client_id>&client_secret=<proxy_client_secret>
 *
 * Body (application/x-www-form-urlencoded):
 *   grant_type  client_credentials  (standard; required by most CredStore configs)
 *   scope       Optional. Forwarded verbatim to the downstream token endpoint.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Environment variables
 * ─────────────────────────────────────────────────────────────────────────────
 *   GCP_PROJECT_ID / GOOGLE_CLOUD_PROJECT
 *       GCP project that owns the Secret Manager secrets.
 *
 *   GSM_SERVICE_ACCOUNT_KEY_JSON  |
 *   GSM_SERVICE_ACCOUNT_EMAIL     |  See secretManager.js for details.
 *   GSM_CACHE_TTL_MS              |
 *
 *   ALLOWED_TARGET_URLS
 *       Comma-separated list of URL prefixes that are permitted as target_url
 *       values.  Any request whose target_url does not start with one of these
 *       prefixes is rejected with HTTP 400.
 *       Example: "https://login.microsoftonline.com,https://accounts.google.com"
 *       Leave unset (or empty) only in local development — in production this
 *       MUST be configured to prevent SSRF attacks.
 */

const functions = require('@google-cloud/functions-framework');
const { getProxyCredentials, getTargetCredentials } = require('./secretManager');
const { getProvider, listProviders } = require('./providers');

// ─── SSRF allowlist ───────────────────────────────────────────────────────────

/**
 * Parses the ALLOWED_TARGET_URLS environment variable into an array of
 * permitted URL prefixes.  An empty array means no restriction (dev only).
 *
 * @returns {string[]}
 */
function getAllowedTargetPrefixes() {
  const raw = process.env.ALLOWED_TARGET_URLS || '';
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Returns true if the supplied URL is permitted by the allowlist.
 * When the allowlist is empty (not configured), all URLs are allowed and a
 * warning is emitted — this state is only acceptable in local development.
 *
 * @param {string} url
 * @returns {boolean}
 */
function isTargetUrlAllowed(url) {
  const prefixes = getAllowedTargetPrefixes();

  if (prefixes.length === 0) {
    console.warn(
      '[Security] ALLOWED_TARGET_URLS is not configured. ' +
      'All target_url values are permitted. Set this variable in production.'
    );
    return true;
  }

  return prefixes.some((prefix) => url.startsWith(prefix));
}

// ─── Helper: parse Basic Auth header ─────────────────────────────────────────

/**
 * Extracts credentials from an HTTP Basic Auth header.
 * Splits on the first colon only (RFC 7617 §2).
 *
 * @param {string} authHeader
 * @returns {{ id: string, secret: string }|null}
 */
function parseBasicAuth(authHeader) {
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;

  const decoded   = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const delimIdx  = decoded.indexOf(':');
  if (delimIdx === -1) return null;

  return {
    id:     decoded.substring(0, delimIdx),
    secret: decoded.substring(delimIdx + 1),
  };
}

// ─── Route: POST /token ───────────────────────────────────────────────────────

/**
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 */
async function handleTokenRequest(req, res) {
  const { target_url, target_id, provider: providerId } = req.query;

  // 1. Required query params.
  if (!target_url || !target_id) {
    return res.status(400).json({
      error:  'missing_query_params',
      detail: '"target_url" and "target_id" are required query parameters.',
    });
  }

  // 2. SSRF guard — validate target_url against the allowlist before anything
  //    else so we don't leak information about what happens next.
  if (!isTargetUrlAllowed(target_url)) {
    console.warn(`[Security] Rejected disallowed target_url: ${target_url}`);
    return res.status(400).json({
      error:  'target_url_not_allowed',
      detail: 'The supplied target_url is not in the list of permitted endpoints.',
    });
  }

  // 3. Extract proxy credentials from the incoming request.
  //    Basic Auth takes precedence over body parameters.
  const basicAuth    = parseBasicAuth(req.headers.authorization || '');
  const incomingId   = basicAuth?.id     ?? req.body?.client_id;
  const incomingSecret = basicAuth?.secret ?? req.body?.client_secret;

  if (!incomingId || !incomingSecret) {
    return res.status(400).json({
      error:  'missing_credentials',
      detail: 'Proxy client_id and client_secret are required.',
    });
  }

  console.log(`[Auth] Validating proxy credential for client_id: ${incomingId}`);

  // 4. Validate proxy credentials against Secret Manager.
  let proxyCreds;
  try {
    proxyCreds = await getProxyCredentials();
  } catch (err) {
    console.error('[SecretManager] Failed to load proxy credentials:', err.message);
    return res.status(500).json({
      error:  'server_error',
      detail: 'Failed to retrieve proxy credentials.',
    });
  }

  if (incomingId !== proxyCreds.clientId || incomingSecret !== proxyCreds.clientSecret) {
    console.warn(`[Security] Unauthorized access attempt by client_id: ${incomingId}`);
    return res.status(401).json({ error: 'invalid_client' });
  }

  // 5. Load downstream credentials from Secret Manager.
  //    The caller (Workday) never provides or sees these values.
  let targetCreds;
  try {
    targetCreds = await getTargetCredentials(target_id);
  } catch (err) {
    console.error(
      `[SecretManager] Failed to load credentials for target_id "${target_id}":`,
      err.message
    );
    // Return a generic error — do not reveal which secret name was missing.
    return res.status(400).json({
      error:  'unknown_target',
      detail: `No credentials found for target_id "${target_id}". ` +
              'Ensure the corresponding secrets exist in Secret Manager.',
    });
  }

  // 6. Resolve the OAuth provider module.
  const provider = getProvider(providerId);

  if (provider.meta.implemented === false) {
    return res.status(501).json({
      error:  'provider_not_implemented',
      detail: `Provider "${provider.meta.id}" is registered but not yet implemented.`,
    });
  }

  console.log(
    `[Proxy] Routing to provider "${provider.meta.id}" → ${target_url} ` +
    `(target_id: ${target_id})`
  );

  // 7. Fetch the downstream token and return it verbatim.
  //    We intentionally do not wrap or reformat the vendor's response so that
  //    Workday receives exactly what the vendor returned — including any
  //    vendor-specific fields and error shapes.
  const scope = req.body?.scope || req.query?.scope;

  try {
    const tokenResponse = await provider.fetchToken({
      targetUrl:       target_url,
      clientId:        targetCreds.clientId,
      clientSecret:    targetCreds.clientSecret,
      scope,
      extraBodyFields: {},
    });

    return res.status(200).json(tokenResponse);
  } catch (err) {
    // Pass the upstream HTTP status and body through verbatim so Workday
    // sees the vendor's actual error rather than a generic wrapper.
    const upstreamStatus = err.response?.status;
    const upstreamBody   = err.response?.data;

    if (upstreamStatus && upstreamBody) {
      console.error(
        `[Provider: ${provider.meta.id}] Upstream ${upstreamStatus} error:`,
        upstreamBody
      );
      return res.status(upstreamStatus).json(upstreamBody);
    }

    // Network-level failure (no HTTP response received).
    console.error(`[Provider: ${provider.meta.id}] Request failed:`, err.message);
    return res.status(502).json({
      error:  'upstream_unreachable',
      detail: 'The downstream token endpoint did not respond.',
    });
  }
}

// ─── Route: GET /providers ────────────────────────────────────────────────────

/**
 * Introspection endpoint — returns registered provider metadata.
 * Requires no authentication; exposes no secrets.
 *
 * @param {import('express').Response} res
 */
function handleProvidersRequest(res) {
  return res.status(200).json({ providers: listProviders() });
}

// ─── Cloud Function entry point ───────────────────────────────────────────────

functions.http('oauthProxy', async (req, res) => {
  const path = req.path.replace(/\/+$/, '') || '/';

  if (path.endsWith('/token') && req.method === 'POST') {
    return handleTokenRequest(req, res);
  }

  if (path.endsWith('/providers') && req.method === 'GET') {
    return handleProvidersRequest(res);
  }

  return res.status(404).send();
});
