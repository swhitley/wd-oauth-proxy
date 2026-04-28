'use strict';

const functions = require('@google-cloud/functions-framework');
const crypto = require('crypto');
const { z } = require('zod');
const ipRangeCheck = require('ip-range-check');
const { LRUCache } = require('lru-cache');

const { getProxySecret, getTargetConfig } = require('./secretManager');
const { getStrategy } = require('./strategies');

/**
 * Structured Logging Utility
 * Integrates with Google Cloud Logging to preserve trace contexts.
 */
function writeLog(severity, reqContext, data, message) {
  const entry = { severity, message, ...data, timestamp: new Date().toISOString() };
  if (reqContext?.traceId && process.env.GOOGLE_CLOUD_PROJECT) {
    entry['logging.googleapis.com/trace'] = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/traces/${reqContext.traceId}`;
  }
  
  if (severity === 'ERROR' || severity === 'CRITICAL') {
    console.error(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

const logger = {
  info: (reqContext, data, message) => writeLog('INFO', reqContext, data, message),
  warn: (reqContext, data, message) => writeLog('WARNING', reqContext, data, message),
  error: (reqContext, data, message) => writeLog('ERROR', reqContext, data, message),
  audit: (reqContext, auditData) => {
    const severity = auditData.statusCode >= 400 ? 'WARNING' : 'NOTICE';
    writeLog(severity, reqContext, { audit_log: true, ...auditData }, 'Proxy request audit');
  }
};

/**
 * Rate Limiting
 * Local in-memory cache to prevent floods. Note: This is per-instance.
 */
const rateLimitCache = new LRUCache({ max: 5000, ttl: 60000 });
const MAX_REQUESTS_PER_MINUTE = parseInt(process.env.RATE_LIMIT_THRESHOLD || '100', 10); 

async function isRateLimited(reqContext, sourceIp, clientId) {
  const key = `${sourceIp}::${clientId || 'anon'}`;
  const currentCount = rateLimitCache.get(key) || 0;
  
  if (currentCount >= MAX_REQUESTS_PER_MINUTE) {
    logger.warn(reqContext, { sourceIp, clientId, currentCount }, 'Rate limit triggered');
    return true;
  }
  
  rateLimitCache.set(key, currentCount + 1);
  return false;
}

/**
 * Token Deduplication and Caching
 * Prevents multiple concurrent requests for the same token (Request Collapsing).
 */
const tokenCache = new LRUCache({ max: 1000 });
const inFlightRequests = new Map();

async function getOrFetchToken(reqContext, clientId, targetId, scope, fetchFn) {
  const key = `${clientId}:${targetId}:${scope || 'default'}`;

  if (tokenCache.has(key)) {
    return tokenCache.get(key);
  }

  if (inFlightRequests.has(key)) {
    logger.info(reqContext, { targetId, scope }, 'Joining in-flight token request');
    return inFlightRequests.get(key);
  }

  const fetchPromise = Promise.resolve()
    .then(() => fetchFn())
    .then((tokenResponse) => {
      let expiresIn = parseInt(tokenResponse.expires_in, 10);
      if (isNaN(expiresIn) || expiresIn <= 0) expiresIn = 3600;
      const ttlMs = Math.max(1000, (expiresIn - 30) * 1000);
      tokenCache.set(key, tokenResponse, { ttl: ttlMs });
      return tokenResponse;
    })
    .finally(() => {
      inFlightRequests.delete(key);
    });

  inFlightRequests.set(key, fetchPromise);
  
  // Ensure we don't leak the map entry if the promise is never resolved/rejected elsewhere
  fetchPromise.catch(() => {}); 

  return fetchPromise;
}

const ALLOWED_WORKDAY_IPS = (process.env.ALLOWED_WORKDAY_IPS || '').split(',').map(ip => ip.trim()).filter(Boolean);
if (ALLOWED_WORKDAY_IPS.length === 0) {
  throw new Error('ALLOWED_WORKDAY_IPS environment variable is required.');
}

const TargetIdSchema = z.string().trim().regex(/^[A-Z0-9_]+$/).max(64);
const ScopeSchema = z.string().trim().regex(/^[a-zA-Z0-9_:\.\/ -]+$/).max(256).optional();

function isIpAllowed(ip) {
  if (!ip) return false;
  return ipRangeCheck(ip, ALLOWED_WORKDAY_IPS);
}

/**
 * Constant-time comparison to prevent timing attacks on secrets
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  try {
    const hashA = crypto.createHash('sha256').update(a).digest();
    const hashB = crypto.createHash('sha256').update(b).digest();
    return crypto.timingSafeEqual(hashA, hashB);
  } catch (e) {
    return false;
  }
}

function parseBasicAuth(authHeader) {
  try {
    const [scheme, credentials] = (authHeader || '').split(' ');
    if (scheme.toLowerCase() !== 'basic' || !credentials) return null;

    const decoded = Buffer.from(credentials, 'base64').toString();
    const colonIndex = decoded.indexOf(':');
    
    if (colonIndex === -1) return { clientId: decoded, clientSecret: '' };
    
    return {
      clientId: decoded.substring(0, colonIndex),
      clientSecret: decoded.substring(colonIndex + 1)
    };
  } catch (e) {
    return null;
  }
}

async function handleTokenRequest(req, res, reqContext) {
  const auditData = {
    sourceIp: req.ip,
    targetId: 'unknown',
    proxyClientId: 'unknown',
    success: false,
    statusCode: 500
  };

  try {
    // Validate Content-Type for POST requests
    const contentType = (req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('application/x-www-form-urlencoded') && !contentType.includes('application/json')) {
      auditData.statusCode = 415;
      return res.status(415).json({ error: 'invalid_request', detail: 'Unsupported Content-Type' });
    }

    let clientId, clientSecret;
    const authHeader = req.headers.authorization;

    if (authHeader) {
      const auth = parseBasicAuth(authHeader);
      if (!auth) {
        auditData.statusCode = 401;
        return res.status(401).json({ error: 'invalid_client', detail: 'Malformed Authorization header' });
      }
      clientId = auth.clientId;
      clientSecret = auth.clientSecret;
    } else {
      clientId = req.body?.client_id;
      clientSecret = req.body?.client_secret;
    }

    if (!clientId || !clientSecret) {
      auditData.statusCode = 401;
      return res.status(401).json({ error: 'invalid_client', detail: 'Missing credentials' });
    }

    auditData.proxyClientId = clientId;

    if (await isRateLimited(reqContext, auditData.sourceIp, clientId)) {
      auditData.statusCode = 429;
      return res.status(429).json({ error: 'too_many_requests' });
    }

    // Param Parsing
    const targetIdInput = req.query.target_id || req.body?.target_id;
    const parsedTargetId = TargetIdSchema.safeParse(targetIdInput);
    if (!parsedTargetId.success) {
      auditData.statusCode = 400;
      return res.status(400).json({ error: 'invalid_request', detail: 'Invalid target_id' });
    }
    
    const target_id = parsedTargetId.data;
    auditData.targetId = target_id;

    const rawScope = req.body?.scope || req.query?.scope;
    const parsedScope = ScopeSchema.safeParse(rawScope);
    if (!parsedScope.success) {
      auditData.statusCode = 400;
      return res.status(400).json({ error: 'invalid_request', detail: 'Invalid scope' });
    }

    // Authenticate Proxy Client
    const proxySecret = await getProxySecret(reqContext, clientId);
    if (!proxySecret || !safeCompare(clientSecret, proxySecret)) {
      auditData.statusCode = 401;
      return res.status(401).json({ error: 'invalid_client', detail: 'Authentication failed' });
    }

    // Fetch Target Config
    const config = await getTargetConfig(reqContext, target_id);
    const activeScope = parsedScope.data || config.default_scope;

    // Scope Authorization
    if (activeScope) {
      if (!Array.isArray(config.allowed_scopes)) {
        auditData.statusCode = 403;
        return res.status(403).json({ error: 'invalid_scope', detail: 'Target misconfigured: missing allowed_scopes' });
      }

      // Handle space-separated lists (Standard OAuth 2.0 behavior)
      const requestedScopes = activeScope.split(' ').filter(Boolean);
      
      // Ensure EVERY requested scope exists in the allowed list
      const isAuthorized = requestedScopes.every(scope => config.allowed_scopes.includes(scope));

      if (!isAuthorized) {
        auditData.statusCode = 403;
        return res.status(403).json({ error: 'invalid_scope' });
      }
    }

    const strategy = getStrategy(config.strategy || 'client_credentials');

    const tokenData = await getOrFetchToken(reqContext, clientId, target_id, activeScope, () => 
      strategy.fetchToken({
        targetUrl: config.target_url,
        clientId: config.client_id,
        clientSecret: config.client_secret,
        scope: activeScope,
      })
    );

    auditData.success = true;
    auditData.statusCode = 200;
    return res.status(200).json(tokenData);

  } catch (err) {
    const isUpstreamError = !!err.response;
    auditData.statusCode = isUpstreamError ? (err.response.status || 502) : 500;
    
    logger.error(reqContext, { 
      message: err.message, 
      stack: err.stack,
      upstreamData: err.response?.data 
    }, 'Token request failed');

    return res.status(auditData.statusCode).json({ 
      error: isUpstreamError ? 'upstream_error' : 'internal_server_error'
    });
  } finally {
    logger.audit(reqContext, auditData);
  }
}

/**
 * Main Function Handler
 */
functions.http('oauthProxy', async (req, res) => {
  // Security Hardening Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'no-referrer');

  const reqContext = { traceId: crypto.randomUUID() };

  if (!isIpAllowed(req.ip)) {
    logger.warn(reqContext, { ip: req.ip }, 'Unauthorized IP access attempt');
    return res.status(403).json({ error: 'access_denied' });
  }

  // Safely match '/token', '/oauthProxy/token', or standard root calls
  const isValidPath = req.path.endsWith('/token') || req.path === '/' || req.path === '';

  if (isValidPath && req.method === 'POST') {
    return handleTokenRequest(req, res, reqContext);
  }
  
  return res.status(404).json({ error: 'not_found' });
});