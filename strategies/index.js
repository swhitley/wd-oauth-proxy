'use strict';

const axios = require('axios');
const axiosRetry = require('axios-retry').default;

const clientCredentials = require('./clientCredentials');
const jwtBearer = require('./jwtBearer');

const httpClient = axios.create({
  timeout: 10000,
});

// FIX [LOW]: The previous retry condition used isNetworkError only, meaning
// transient 5xx responses from the upstream IdP were never retried. This patch
// adds isRetryableError (covers 5xx) while explicitly excluding 4xx responses.
// Retrying on 401/403 would be harmful: it would amplify credential probing
// attempts and mask real configuration errors with delayed failures. Retrying
// on 429 is also excluded because the upstream IdP's rate limit should be
// respected rather than hammered.
axiosRetry(httpClient, {
  retries: 3,
  retryDelay: (retryCount) => {
    const delay = axiosRetry.exponentialDelay(retryCount);
    const jitter = Math.floor(Math.random() * 100);
    return delay + jitter;
  },
  retryCondition: (error) => {
    // Never retry on client errors (4xx) — these indicate bad credentials,
    // missing scopes, or invalid requests that will not succeed on retry.
    if (error.response && error.response.status >= 400 && error.response.status < 500) {
      return false;
    }
    // Retry on network-level failures or upstream 5xx responses.
    return axiosRetry.isNetworkError(error) || axiosRetry.isRetryableError(error);
  }
});

const STRATEGIES = {
  'client_credentials': {
    fetchToken: (args) => clientCredentials.fetchToken({ ...args, httpClient })
  },
  'jwt_bearer': {
    fetchToken: (args) => jwtBearer.fetchToken({ ...args, httpClient })
  },
};

function getStrategy(strategyId) {
  const strategy = STRATEGIES[strategyId];
  if (!strategy) {
    throw new Error(`Unknown authentication strategy specified: "${strategyId}"`);
  }
  return strategy;
}

module.exports = { getStrategy };
