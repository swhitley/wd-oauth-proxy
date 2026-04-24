'use strict';

/**
 * secretManager.js
 *
 * Wraps Google Cloud Secret Manager with:
 *   - Explicit service account support (JSON key or impersonation).
 *   - Per-secret in-memory caching with a configurable TTL so the function
 *     does not call GSM on every request for values that rarely change.
 *   - A helper that loads downstream target credentials by target_id so that
 *     no downstream secrets ever need to pass through Workday's CredStore.
 *
 * Environment variables:
 *   GCP_PROJECT_ID / GOOGLE_CLOUD_PROJECT   – Project STRING ID (not number).
 *   GSM_SERVICE_ACCOUNT_KEY_JSON  – Full SA JSON key (Secret Accessor role).
 *   GSM_SERVICE_ACCOUNT_EMAIL     – SA email to impersonate via ADC.
 *   GSM_CACHE_TTL_MS              – Cache TTL in ms. Default: 300000 (5 min).
 *
 * Secret naming convention:
 *   PROXY_CLIENT_ID                  – Proxy's own client_id.
 *   PROXY_CLIENT_SECRET              – Proxy's own client_secret.
 *   TARGET_<TARGET_ID>_CLIENT_ID     – Downstream client_id.
 *   TARGET_<TARGET_ID>_CLIENT_SECRET – Downstream client_secret.
 */

const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const { GoogleAuth, Impersonated }    = require('google-auth-library');

// ─── Client initialisation ────────────────────────────────────────────────────

/**
 * Stores a Promise<SecretManagerServiceClient> rather than the client itself.
 * This ensures concurrent cold-start requests all await the same single
 * initialisation rather than racing to create multiple clients.
 *
 * @type {Promise<SecretManagerServiceClient> | null}
 */
let _clientPromise = null;

/**
 * Returns a promise that resolves to the singleton SecretManagerServiceClient.
 *
 * Credentials are resolved in priority order:
 *   1. GSM_SERVICE_ACCOUNT_KEY_JSON  (explicit JSON key)
 *   2. GSM_SERVICE_ACCOUNT_EMAIL     (SA impersonation via ADC)
 *   3. ADC / runtime SA              (fallback)
 *
 * WHY THIS IS ASYNC (lesson learned):
 *   The Impersonated class requires a fully resolved OAuth2Client as its
 *   sourceClient — NOT a GoogleAuth factory instance.  Passing GoogleAuth
 *   directly left the universe domain unresolved, producing the malformed
 *   endpoint "iamcredentials.undefined".  The fix is:
 *     const resolvedClient = await baseAuth.getClient();
 *   before constructing Impersonated.
 *
 * @returns {Promise<SecretManagerServiceClient>}
 */
function getClientPromise() {
  if (_clientPromise) return _clientPromise;

  _clientPromise = (async () => {

    // Option A: explicit JSON key ─────────────────────────────────────────────
    if (process.env.GSM_SERVICE_ACCOUNT_KEY_JSON) {
      let keyFile;
      try {
        keyFile = JSON.parse(process.env.GSM_SERVICE_ACCOUNT_KEY_JSON);
      } catch (err) {
        throw new Error(
          'GSM_SERVICE_ACCOUNT_KEY_JSON is set but contains invalid JSON: ' + err.message
        );
      }
      const auth = new GoogleAuth({
        credentials: keyFile,
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      });
      console.log(`[SecretManager] Using explicit JSON key for SA: ${keyFile.client_email}`);
      return new SecretManagerServiceClient({ auth });
    }

    // Option B: SA impersonation via ADC ──────────────────────────────────────
    if (process.env.GSM_SERVICE_ACCOUNT_EMAIL) {
      const targetSA = process.env.GSM_SERVICE_ACCOUNT_EMAIL;

      const baseAuth = new GoogleAuth({
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      });

      // CRITICAL: must await getClient() to obtain a concrete OAuth2Client.
      // GoogleAuth is a factory. Impersonated.sourceClient must be the
      // resolved credential object — not the factory itself.
      const resolvedBaseClient = await baseAuth.getClient();

      const impersonated = new Impersonated({
        sourceClient:    resolvedBaseClient,
        targetPrincipal: targetSA,
        lifetime:        3600,
        delegates:       [],
        targetScopes:    ['https://www.googleapis.com/auth/cloud-platform'],
      });

      console.log(`[SecretManager] Impersonating SA: ${targetSA}`);
      return new SecretManagerServiceClient({ authClient: impersonated });
    }

    // Option C: ADC / runtime SA fallback ─────────────────────────────────────
    console.warn(
      '[SecretManager] No explicit SA configured – falling back to ADC / runtime SA. ' +
      'Set GSM_SERVICE_ACCOUNT_KEY_JSON or GSM_SERVICE_ACCOUNT_EMAIL in production.'
    );
    return new SecretManagerServiceClient();

  })();

  // On failure, clear the cached promise so the next request can retry
  // rather than permanently serving the same rejection.
  _clientPromise.catch(() => { _clientPromise = null; });

  return _clientPromise;
}

// ─── In-memory cache ──────────────────────────────────────────────────────────

/** @type {Map<string, { value: string, expiresAt: number }>} */
const _cache = new Map();

const CACHE_TTL_MS = (() => {
  const raw = parseInt(process.env.GSM_CACHE_TTL_MS ?? '300000', 10);
  return Number.isFinite(raw) && raw >= 0 ? raw : 300_000;
})();

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolves the GCP project ID from environment variables.
 *
 * IMPORTANT: Must be the string project ID (e.g. "my-project"), NOT the
 * numeric project number.  Secret Manager resource paths require the string
 * form — using the number produces silent lookup failures.
 *
 * @returns {string}
 */
function resolveProjectId() {
  const id = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
  if (!id) {
    throw new Error(
      'GCP project ID not set. Provide GCP_PROJECT_ID or GOOGLE_CLOUD_PROJECT ' +
      'as the string project ID (e.g. "my-project"), not the numeric project number.'
    );
  }
  return id;
}

// ─── Core fetch ───────────────────────────────────────────────────────────────

/**
 * Fetches the latest version of a secret from GSM, returning a cached value
 * if one exists and has not yet expired.
 *
 * @param {string} secretName - Short secret name (not the full resource path).
 * @returns {Promise<string>} Secret payload as a UTF-8 string.
 */
async function getSecret(secretName) {
  if (CACHE_TTL_MS > 0) {
    const entry = _cache.get(secretName);
    if (entry && Date.now() < entry.expiresAt) {
      return entry.value;
    }
  }

  const client    = await getClientPromise();
  const projectId = resolveProjectId();
  const name      = `projects/${projectId}/secrets/${secretName}/versions/latest`;

  try {
    const [version] = await client.accessSecretVersion({ name });
    const value = version.payload.data.toString('utf8');

    if (CACHE_TTL_MS > 0) {
      _cache.set(secretName, { value, expiresAt: Date.now() + CACHE_TTL_MS });
    }

    return value;
  } catch (err) {
    console.error(`[SecretManager] Failed to fetch "${secretName}":`, err.message);
    throw err;
  }
}

// ─── Target credential helpers ────────────────────────────────────────────────

/**
 * Normalises a target_id into the prefix used for Secret Manager key names.
 * Non-alphanumeric characters (except _) are replaced with _ and uppercased.
 *
 * @example  normaliseTargetId('acme-hr') → 'ACME_HR'
 * @param {string} targetId
 * @returns {string}
 */
function normaliseTargetId(targetId) {
  return targetId.replace(/[^a-zA-Z0-9_]/g, '_').toUpperCase();
}

/**
 * Fetches the downstream client_id and client_secret for a given target.
 * Both values are cached independently under their own TTLs.
 *
 * @param {string} targetId - The raw ?target_id= value from the request.
 * @returns {Promise<{ clientId: string, clientSecret: string }>}
 */
async function getTargetCredentials(targetId) {
  const prefix = normaliseTargetId(targetId);
  const [clientId, clientSecret] = await Promise.all([
    getSecret(`TARGET_${prefix}_CLIENT_ID`),
    getSecret(`TARGET_${prefix}_CLIENT_SECRET`),
  ]);
  return { clientId, clientSecret };
}

/**
 * Fetches the proxy's own client_id and client_secret from Secret Manager.
 *
 * @returns {Promise<{ clientId: string, clientSecret: string }>}
 */
async function getProxyCredentials() {
  const [clientId, clientSecret] = await Promise.all([
    getSecret('PROXY_CLIENT_ID'),
    getSecret('PROXY_CLIENT_SECRET'),
  ]);
  return { clientId, clientSecret };
}

// ─── Cache management ─────────────────────────────────────────────────────────

/**
 * Clears one or all entries from the in-memory secret cache and optionally
 * resets the client promise so the next call re-initialises the GSM client.
 *
 * @param {string} [secretName] - If omitted, the entire cache is cleared.
 */
function clearCache(secretName) {
  if (secretName) {
    _cache.delete(secretName);
  } else {
    _cache.clear();
    _clientPromise = null;
  }
}

module.exports = {
  getSecret,
  getTargetCredentials,
  getProxyCredentials,
  clearCache,
  normaliseTargetId,
};
