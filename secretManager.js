'use strict';

const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const { LRUCache } = require('lru-cache');

const CACHE_TTL_MS = parseInt(process.env.GSM_CACHE_TTL_MS ?? '300000', 10);
const secretCache = new LRUCache({
  max: 500,
  ttl: CACHE_TTL_MS > 0 ? CACHE_TTL_MS : undefined,
});

let _client = null;

function getClient() {
  if (!_client) _client = new SecretManagerServiceClient();
  return _client;
}

function resolveProjectId() {
  const id = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
  if (!id) throw new Error('GCP_PROJECT_ID is not configured.');
  return id;
}

const ALLOWED_TARGET_HOSTS = (process.env.ALLOWED_TARGET_HOSTS || '')
  .split(',')
  .map(h => h.trim().toLowerCase())
  .filter(Boolean);

if (ALLOWED_TARGET_HOSTS.length === 0) {
  throw new Error('ALLOWED_TARGET_HOSTS is required to prevent SSRF.');
}

async function getSecret(reqContext, secretName) {
  if (secretCache.has(secretName)) return secretCache.get(secretName);

  const client = getClient();
  const projectId = resolveProjectId();
  const name = `projects/${projectId}/secrets/${secretName}/versions/latest`;

  try {
    const [version] = await client.accessSecretVersion({ name });
    const value = version.payload.data.toString('utf8');
    secretCache.set(secretName, value);
    return value;
  } catch (err) {
    console.error(JSON.stringify({
      severity: 'ERROR',
      message: `Failed to access secret: ${secretName}`,
      error: err.message,
      traceId: reqContext?.traceId
    }));
    throw err;
  }
}

/**
 * Retrieves and validates target configuration from Secret Manager
 */
async function getTargetConfig(reqContext, targetId) {
  const rawValue = await getSecret(reqContext, `TARGET_${targetId}`);
  
  try {
    const config = JSON.parse(rawValue);
    const parsedUrl = new URL(config.target_url);

    if (parsedUrl.protocol !== 'https:') {
      throw new Error('Targets must use HTTPS');
    }

    // Hostname Validation (SSRF Protection)
    const targetHost = parsedUrl.hostname.toLowerCase();
    const isAllowed = ALLOWED_TARGET_HOSTS.some(allowed => 
      targetHost === allowed || targetHost.endsWith(`.${allowed}`)
    );

    if (!isAllowed) {
      throw new Error(`Hostname ${targetHost} is not in the allowed list`);
    }
    
    return config;
  } catch (err) {
    throw new Error(`Invalid configuration for target ${targetId}: ${err.message}`);
  }
}

/**
 * Retrieves proxy client credentials from a centralized JSON secret
 */
async function getProxySecret(reqContext, clientId) {
  const rawValue = await getSecret(reqContext, 'PROXY_CREDENTIALS');
  try {
    const credentials = JSON.parse(rawValue);
    // Support nested environment keys or a flat client mapping
    for (const key of Object.keys(credentials)) {
      const entry = credentials[key];
      if (entry?.client_id === clientId) return entry.client_secret;
    }
    return null;
  } catch (err) {
    throw new Error('PROXY_CREDENTIALS secret is not valid JSON');
  }
}

module.exports = { getTargetConfig, getProxySecret };