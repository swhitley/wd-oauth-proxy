'use strict';

const functions = require('@google-cloud/functions-framework');
const crypto = require('crypto');
const { z } = require('zod');
const ipRangeCheck = require('ip-range-check');
const { LRUCache } = require('lru-cache');

const { getProxySecret, getTargetConfig } = require('./secretManager');
const { getStrategy } = require('./strategies');

// ============================================================================
// 1. LOGGER UTILITY
// ============================================================================
function writeLog(severity, reqContext, data, message) {
  const entry = { severity, message, ...data };
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
    const severity = auditData.statusCode >= 400 ? 'ERROR' : 'NOTICE';
    writeLog(severity, reqContext, { audit_log: true, ...auditData }, 'OAuth Proxy Audit Event');
  }
};

// ============================================================================
// 2. RATE LIMITER UTILITY
// ============================================================================
const rateLimitCache = new LRUCache({ max: 5000, ttl: 60000 });
const MAX_REQUESTS_PER_MINUTE = 100; 

async function isRateLimited(reqContext, sourceIp, clientId) {
  const key = `${sourceIp}::${clientId || 'unauthenticated'}`;
  const currentCount = rateLimitCache.get(key) || 0;
  
  if (currentCount >= MAX_REQUESTS_PER_MINUTE) {
    logger.warn(reqContext, { sourceIp, clientId, currentCount }, '[RateLimiter] Exceeded per-instance rate limit');
    return true;
  }
  
  rateLimitCache.set(key, currentCount + 1);
  return false;
}

// ============================================================================
// 3. TOKEN CACHE UTILITY
// ============================================================================
const tokenCache = new LRUCache({ max: 1000 });
const inFlightRequests = new Map();

async function getOrFetchToken(reqContext, clientId, targetId, scope, fetchFn) {
  const key = `${clientId}::${targetId}::${scope || 'default'}`;

  if (tokenCache.has(key)) {
    logger.info(reqContext, { targetId, scope }, '[TokenCache] Cache hit');
    return tokenCache.get(key);
  }

  if (inFlightRequests.has(key)) {
    logger.info(reqContext, { targetId, scope }, '[TokenCache] Attaching to in-flight request');
    return inFlightRequests.get(key);
  }

  logger.info(reqContext, { targetId, scope }, '[TokenCache] Cache miss, fetching upstream');
  const fetchPromise = fetchFn()
    .then((tokenResponse) => {
      let expiresIn = parseInt(tokenResponse.expires_in, 10);
      if (isNaN(expiresIn) || expiresIn <= 0) {
        logger.warn(reqContext, { targetId }, '[TokenCache] Upstream missing expires_in. Defaulting to 3600s.');
        expiresIn = 3600;
      }
      const bufferSeconds = 30;
      const ttlMs = Math.max(1, expiresIn - bufferSeconds) * 1000;
      
      tokenCache.set(key, tokenResponse, { ttl: ttlMs });
      logger.info(reqContext, { targetId, scope, ttlMs }, '[TokenCache] Token cached successfully');
      
      return tokenResponse;
    })
    .finally(() => {
      inFlightRequests.delete(key);
    });

  inFlightRequests.set(key, fetchPromise);
  return fetchPromise;
}

// ============================================================================
// 4. CORE PROXY LOGIC
// ============================================================================
const ALLOWED_WORKDAY_IPS = (process.env.ALLOWED_WORKDAY_IPS || '').split(',').map(ip => ip.trim()).filter(Boolean);
if (ALLOWED_WORKDAY_IPS.length === 0) {
  throw new Error('FATAL: ALLOWED_WORKDAY_IPS environment variable must be set. Proxy cannot fail open.');
}

const TargetIdSchema = z.string().regex(/^[A-Z0-9_]+$/, "Invalid format").max(64);
const ScopeSchema = z.string().regex(/^[a-zA-Z0-9_:\.\/ -]+$/, "Invalid scope characters").max(256).optional();

function isIpAllowed(ip) {
  return ipRangeCheck(ip, ALLOWED_WORKDAY_IPS);
}

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  
  // Hash both inputs to fixed-length SHA-256 digests to prevent length-based early exits
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  
  return crypto.timingSafeEqual(hashA, hashB);
}

function parseBasicAuth(authHeader) {
  const b64auth = (authHeader || '').split(' ')[1] || '';
  const decoded = Buffer.from(b64auth, 'base64').toString();
  
  // Isolate on the first colon to preserve any colons within the secret itself
  const colonIndex = decoded.indexOf(':');
  if (colonIndex === -1) {
    return { clientId: decoded, clientSecret: '' };
  }
  
  return {
    clientId: decoded.substring(0, colonIndex),
    clientSecret: decoded.substring(colonIndex + 1)
  };
}

function getTraceContext() {
  return { traceId: crypto.randomUUID() };
}

function getRealIp(req) {
  return req.ip;
}

async function handleTokenRequest(req, res, reqContext) {
  const auditData = {
    sourceIp: getRealIp(req),
    targetId: 'unparsed',
    proxyClientId: 'unknown',
    scope: 'none',
    success: false,
    statusCode: 500,
    failReason: 'unknown'
  };

  try {
    if (req.method !== 'GET') {
      const contentType = (req.headers['content-type'] || '').toLowerCase();
      if (!contentType.includes('application/x-www-form-urlencoded') && !contentType.includes('application/json')) {
        auditData.statusCode = 415;
        auditData.failReason = 'unsupported_media_type';
        return res.status(415).json({ error: 'invalid_request', detail: 'Unsupported Content-Type. Use application/x-www-form-urlencoded or application/json.' });
      }
    }

    let clientId = null;
    let clientSecret = null;
    
    // Extract credentials from Header OR Body
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader) {
      const auth = parseBasicAuth(authHeader);
      if (!auth) {
        auditData.statusCode = 401;
        auditData.failReason = 'malformed_auth_header';
        return res.status(401).json({ error: 'invalid_client', detail: 'Authorization header is present but malformed. Must be valid Basic Auth.' });
      }
      clientId = auth.clientId;
      clientSecret = auth.clientSecret;
    } else if (req.body && req.body.client_id && req.body.client_secret) {
      clientId = req.body.client_id;
      clientSecret = req.body.client_secret;
    }

    if (!clientId || !clientSecret) {
      auditData.statusCode = 401;
      auditData.failReason = 'missing_credentials';
      return res.status(401).json({ error: 'invalid_client', detail: 'Missing client credentials. Provide Authorization header or client_id and client_secret in the body.' });
    }

    auditData.proxyClientId = clientId;

    if (await isRateLimited(reqContext, auditData.sourceIp, clientId)) {
      auditData.statusCode = 429;
      auditData.failReason = 'rate_limit_exceeded';
      return res.status(429).json({ error: 'too_many_requests', detail: 'Rate limit exceeded.' });
    }

    // Allow target_id to come from query string or body
    const targetIdInput = req.query.target_id || req.body?.target_id;
    const parsedTargetId = TargetIdSchema.safeParse(targetIdInput);
    if (!parsedTargetId.success) {
      auditData.statusCode = 400;
      auditData.failReason = 'invalid_target_id';
      return res.status(400).json({ error: 'invalid_request', detail: 'Invalid target_id format.' });
    }
    const target_id = parsedTargetId.data;
    auditData.targetId = target_id;

    const rawScope = req.body?.scope || req.query?.scope;
    const parsedScope = ScopeSchema.safeParse(rawScope);
    if (!parsedScope.success) {
      auditData.statusCode = 400;
      auditData.failReason = 'invalid_scope';
      return res.status(400).json({ error: 'invalid_request', detail: 'Invalid scope format.' });
    }

    const proxySecret = await getProxySecret(reqContext, clientId);
    if (!proxySecret || !safeCompare(clientSecret, proxySecret)) {
      logger.error(reqContext, {}, '[Security] Invalid proxy credentials supplied');
      auditData.statusCode = 401;
      auditData.failReason = 'invalid_credentials';
      return res.status(401).json({ error: 'invalid_client', detail: 'Proxy authentication failed.' });
    }

    let config;
    try {
      config = await getTargetConfig(reqContext, target_id);
    } catch (err) {
      auditData.statusCode = 404;
      auditData.failReason = 'target_not_found';
      return res.status(404).json({ error: 'target_not_found', detail: 'Target configuration not found.' });
    }

    // UPDATED to use snake_case from JSON configuration
    const activeScope = parsedScope.data || config.default_scope;
    auditData.scope = activeScope;

    if (activeScope) {
      // UPDATED to use snake_case from JSON configuration
      if (!Array.isArray(config.allowed_scopes) || !config.allowed_scopes.includes(activeScope)) {
        logger.error(reqContext, { target_id, activeScope }, '[Security] Requested scope is not in the allowed_scopes list for this target');
        auditData.statusCode = 403;
        auditData.failReason = 'unauthorized_scope';
        return res.status(403).json({ error: 'invalid_scope', detail: 'The requested scope is not permitted for this target.' });
      }
    }

    let strategy;
    try {
      strategy = getStrategy(config.strategy || 'client_credentials');
    } catch (err) {
      logger.error(reqContext, { err: err.message, strategy: config.strategy }, 'Strategy resolution failed');
      auditData.statusCode = 500;
      auditData.failReason = 'invalid_strategy_config';
      return res.status(500).json({ error: 'configuration_error', detail: 'Invalid strategy configured.' });
    }

    try {
      const fetchFn = () => strategy.fetchToken({
        targetUrl: config.target_url,
        clientId: config.client_id,
        clientSecret: config.client_secret,
        scope: activeScope,
      });

      const tokenData = await getOrFetchToken(reqContext, clientId, target_id, activeScope, fetchFn);

      auditData.success = true;
      auditData.statusCode = 200;
      auditData.failReason = null;
      return res.status(200).json(tokenData);

    } catch (err) {
      const upstreamStatus = err.response?.status || 502;
      logger.error(reqContext, { 
        err: err.message, target_id, rawUpstreamData: err.response?.data, upstreamStatus 
      }, 'Downstream exchange failed');
      
      auditData.statusCode = upstreamStatus;
      auditData.failReason = 'upstream_rejection';
      return res.status(upstreamStatus).json({ 
        error: 'upstream_exchange_failed', detail: 'The downstream identity provider rejected the request.' 
      });
    }

  } catch (fatalErr) {
    logger.error(reqContext, { err: fatalErr.message, stack: fatalErr.stack }, 'Unhandled execution error');
    auditData.statusCode = 500;
    auditData.failReason = 'internal_exception';
    return res.status(500).json({ error: 'server_error', detail: 'An unexpected error occurred.' });
  } finally {
    logger.audit(reqContext, auditData);
  }
}

functions.http('oauthProxy', async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'no-referrer');

  const reqContext = getTraceContext();
  const sourceIp = getRealIp(req);

  if (!isIpAllowed(sourceIp)) {
    logger.warn(reqContext, { sourceIp }, '[Security] Request blocked at network perimeter');
    return res.status(403).json({ error: 'access_denied', detail: 'IP address not authorized.' });
  }

  if (req.path.endsWith('/token') && req.method === 'POST') {
    return handleTokenRequest(req, res, reqContext);
  }
  
  return res.status(404).json({ error: 'not_found' });
});