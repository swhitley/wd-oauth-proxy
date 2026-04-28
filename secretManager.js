'use strict';

const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const { LRUCache } = require('lru-cache');

function logError(reqContext, data, message) {
  const entry = { severity: 'ERROR', message, ...data };
  if (reqContext?.traceId && process.env.GOOGLE_CLOUD_PROJECT) {
    entry['logging.googleapis.com/trace'] = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/traces/${reqContext.traceId}`;
  }
  console.error(JSON.stringify(entry));
}

// FIX [MEDIUM]: The previous default of 300,000ms (5 minutes) creates a window
// in which a rotated or revoked secret remains valid on every warm instance.
// The default is now 60,000ms (1 minute) to bound the revocation lag.
// Operators who need a longer cache for cost/latency reasons must explicitly
// opt in by setting GSM_CACHE_TTL_MS. Set to 0 to disable caching entirely
// (not recommended in production due to Secret Manager quota limits).
//
// For near-instant revocation, set GSM_CACHE_TTL_MS=0 AND subscribe to
// Secret Manager Pub/Sub rotation events to call a /cache-bust endpoint
// (not implemented here — see runbook section 4).
const CACHE_TTL_MS = parseInt(process.env.GSM_CACHE_TTL_MS ?? '60000', 10);

const secretCache = new LRUCache({
  max: 500,
  ttl: CACHE_TTL_MS > 0 ? CACHE_TTL_MS : 1,
});

let _clientPromise = null;
let _clientInitFailedAt = 0;

function getClientPromise() {
  if (_clientPromise) return _clientPromise;

  if (Date.now() - _clientInitFailedAt < 5000) {
    return Promise.reject(new Error('SecretManager initialization is in backoff state.'));
  }

  try {
    const client = new SecretManagerServiceClient();
    _clientPromise = Promise.resolve(client);
  } catch (err) {
    logError(null, { err: err.message }, '[SecretManager] Client initialization failed.');
    _clientPromise = null;
    _clientInitFailedAt = Date.now();
    return Promise.reject(err);
  }

  return _clientPromise;
}

function resolveProjectId() {
  const id = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
  if (!id) throw new Error('GCP project ID not set in environment.');
  return id;
}

const ALLOWED_TARGET_HOSTS = (process.env.ALLOWED_TARGET_HOSTS || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
if (ALLOWED_TARGET_HOSTS.length === 0) {
  throw new Error('FATAL: ALLOWED_TARGET_HOSTS environment variable must be set.');
}

async function getSecret(reqContext, secretName) {
  if (CACHE_TTL_MS > 0 && secretCache.has(secretName)) {
    return secretCache.get(secretName);
  }

  const client = await getClientPromise();
  const projectId = resolveProjectId();
  const name = `projects/${projectId}/secrets/${secretName}/versions/latest`;

  try {
    const [version] = await client.accessSecretVersion({ name });
    const value = version.payload.data.toString('utf8');
    if (CACHE_TTL_MS > 0) secretCache.set(secretName, value);
    return value;
  } catch (err) {
    logError(reqContext, { err: err.message, secretName }, '[SecretManager] Secret retrieval failed');
    throw err;
  }
}

async function getTargetConfig(reqContext, targetId) {
  const secretName = `TARGET_${targetId}`;
  const rawValue = await getSecret(reqContext, secretName);

  try {
    const parsedConfig = JSON.parse(rawValue);

    const parsedUrl = new URL(parsedConfig.target_url);
    if (parsedUrl.protocol !== 'https:') {
      throw new Error('target_url must use HTTPS.');
    }

    const isAllowed = ALLOWED_TARGET_HOSTS.some(host => {
      const cleanHost = host.toLowerCase().trim();
      const targetHost = parsedUrl.hostname.toLowerCase();
      return targetHost === cleanHost || targetHost.endsWith(`.${cleanHost}`);
    });

    if (!isAllowed) {
      logError(reqContext, { hostname: parsedUrl.hostname }, '[Security] SSRF block: Hostname not in allowlist');
      throw new Error('target_url hostname is not in the allowlist.');
    }

    return parsedConfig;
  } catch (err) {
    logError(reqContext, { targetId, err: err.message }, '[SecretManager] Target config is invalid or malformed');
    throw new Error('Configuration payload is invalid or malformed.');
  }
}

async function getProxySecret(reqContext, clientId) {
  const rawValue = await getSecret(reqContext, 'PROXY_CREDENTIALS');
  try {
    const credentialsObj = JSON.parse(rawValue);

    for (const envName of Object.keys(credentialsObj)) {
      const envData = credentialsObj[envName];
      if (envData && envData.client_id === clientId) {
        return envData.client_secret;
      }
    }

    return null;
  } catch (err) {
    logError(reqContext, {}, '[SecretManager] Proxy credentials secret is malformed');
    throw new Error('Proxy credentials payload is malformed.');
  }
}

module.exports = { getTargetConfig, getProxySecret };
