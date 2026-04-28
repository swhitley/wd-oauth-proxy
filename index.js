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
// FIX [HIGH]: The in-process LRU counter is per-instance. In a multi-instance
// Cloud Functions deployment each instance enforces the limit independently,
// meaning the effective ceiling is (MAX_REQUESTS_PER_MINUTE x instance count).
// This implementation is intentionally left as a best-effort local defence
// (e.g. against a single client hammering one warm instance) but MUST be
// supplemented by a shared counter in Cloud Memorystore (Redis) or by GCP
// Cloud Armor / API Gateway rate-limiting rules before this service handles
// production traffic. See ADR-0012 for the migration plan.
// ============================================================================
const rateLimitCache = new LRUCache({ max: 5000, ttl: 60000 });
const MAX_REQUESTS_PER_MINUTE = 100;

// Warn loudly at startup so the gap is always visible in logs.
writeLog('WARNING', null, { component: 'RateLimiter', action: 'startup_check' },
  '[RateLimiter] NOTICE: rate limiting is per-instance. Deploy a shared Redis counter ' +
  'or Cloud Armor policy before going to production.');

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
// FIX [CRITICAL]: clientId was referenced but never declared in this function's
// scope, causing a ReferenceError on every invocation. It is now an explicit
// parameter, which also correctly scopes cache keys per proxy caller so that
// two different clients targeting the same target_id and scope cannot share
// each other's cached tokens.
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
const ScopeSchema = z.string().regex(/^[a-zA-Z0-9_:\\.\\/ -]+$/, "Invalid scope characters").max(256).optional();

function isIpAllowed(ip) {
  return ipRangeCheck(ip, ALLOWED_WORKDAY_IPS);
}

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function parseBasicAuth(authHeader) {
  const b64auth = (authHeader || '').split(' ')[1] || '';
  const decoded = Buffer.from(b64auth, 'base64').toString();

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
    const contentType = (req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('application/x-www-form-urlencoded') && !contentType.includes('application/json')) {
      auditData.statusCode = 415;
      auditData.failReason = 'unsupported_media_type';
      return res.status(415).json({ error: 'invalid_request', detail: 'Unsupported Content-Type. Use application/x-www-form-urlencoded or application/json.' });
    }

    // FIX [HIGH]: Credentials are now accepted exclusively via the HTTP Basic
    // Auth header (RFC 6749 s.2.3.1 preferred method). Accepting client_id /
    // client_secret in the POST body risks credential capture in reverse-proxy
    // access logs, middleware request dumps, and APM payloads.
    //
    // FIX [LOW]: Node.js normalises all incoming header names to lowercase, so
    // req.headers.Authorization is always undefined. The dead uppercase fallback
    // has been removed.
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      auditData.statusCode = 401;
      auditData.failReason = 'missing_credentials';
      return res.status(401).json({
        error: 'invalid_client',
        detail: 'Missing Authorization header. Credentials must be supplied via HTTP Basic Auth.'
      });
    }

    const auth = parseBasicAuth(authHeader);
    if (!auth || !auth.clientId || !auth.clientSecret) {
      auditData.statusCode = 401;
      auditData.failReason = 'malformed_auth_header';
      return res.status(401).json({ error: 'invalid_client', detail: 'Authorization header is present but malformed. Must be valid Basic Auth.' });
    }

    const clientId = auth.clientId;
    const clientSecret = auth.clientSecret;
    auditData.proxyClientId = clientId;

    if (await isRateLimited(reqContext, auditData.sourceIp, clientId)) {
      auditData.statusCode = 429;
      auditData.failReason = 'rate_limit_exceeded';
      return res.status(429).json({ error: 'too_many_requests', detail: 'Rate limit exceeded.' });
    }

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

    const activeScope = parsedScope.data || config.default_scope;
    auditData.scope = activeScope;

    // FIX [MEDIUM]: The previous `if (activeScope)` guard silently skipped the
    // allowlist check when no scope could be resolved from either the request or
    // the target config. A scopeless request may obtain a broader token than
    // intended depending on the IdP's default behaviour. We now require a scope
    // to be resolvable and reject requests that cannot produce one.
    if (!activeScope) {
      logger.error(reqContext, { target_id }, '[Security] No scope resolvable from request or target config');
      auditData.statusCode = 400;
      auditData.failReason = 'scope_required';
      return res.status(400).json({
        error: 'invalid_request',
        detail: 'A scope is required. Provide one in the request or set default_scope in the target configuration.'
      });
    }

    if (!Array.isArray(config.allowed_scopes) || !config.allowed_scopes.includes(activeScope)) {
      logger.error(reqContext, { target_id, activeScope }, '[Security] Requested scope is not in the allowed_scopes list for this target');
      auditData.statusCode = 403;
      auditData.failReason = 'unauthorized_scope';
      return res.status(403).json({ error: 'invalid_scope', detail: 'The requested scope is not permitted for this target.' });
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

      // FIX [CRITICAL]: clientId is now passed as a parameter. Previously this
      // call threw ReferenceError: clientId is not defined.
      const tokenData = await getOrFetchToken(reqContext, clientId, target_id, activeScope, fetchFn);

      auditData.success = true;
      auditData.statusCode = 200;
      auditData.failReason = null;
      return res.status(200).json(tokenData);

    } catch (err) {
      // FIX [HIGH]: The upstream HTTP status was previously forwarded verbatim
      // to the caller (e.g. a 401 from Workday's IdP). This leaks information
      // about downstream system state and enables oracle-style probing of target
      // configurations. All upstream failures are now normalised to 502 (bad
      // gateway) or 504 (timeout). The raw upstream status is logged internally
      // for debugging but never returned to the caller.
      const isTimeout = err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT';
      const internalStatus = err.response?.status || (isTimeout ? 504 : 502);
      const normalizedStatus = isTimeout ? 504 : 502;

      logger.error(reqContext, {
        err: err.message,
        target_id,
        upstreamStatus: internalStatus,
        isTimeout,
      }, 'Downstream exchange failed');

      auditData.statusCode = normalizedStatus;
      auditData.failReason = 'upstream_rejection';
      return res.status(normalizedStatus).json({
        error: 'upstream_exchange_failed',
        detail: isTimeout
          ? 'The downstream identity provider did not respond in time.'
          : 'The downstream identity provider rejected the request.'
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

  // FIX [MEDIUM]: If the function is invoked without a GCP-managed load
  // balancer in front (e.g. a direct Cloud Run URL), req.ip may resolve from a
  // spoofed X-Forwarded-For header, defeating the IP allowlist entirely. Set
  // EXPECTED_TRUST_PROXY=true when deploying behind GCP LB, and ensure ingress
  // is restricted to internal/load-balancer traffic only in Cloud Functions
  // settings. The check here surfaces a misconfiguration as a startup warning
  // rather than silently failing open.
  if (process.env.EXPECTED_TRUST_PROXY === 'true' && !req.app?.get('trust proxy')) {
    writeLog('WARNING', null, { component: 'IpAllowlist' },
      '[Security] EXPECTED_TRUST_PROXY is set but Express trust proxy is not enabled. ' +
      'req.ip may be spoofable. Ensure ingress is restricted to load-balancer traffic only.');
  }

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
