'use strict';

const axios = require('axios');
const axiosRetry = require('axios-retry').default;

const clientCredentials = require('./clientCredentials');
const jwtBearer = require('./jwtBearer');

// Configure resilient HTTP client for upstream identity providers
const httpClient = axios.create({
  timeout: 10000, 
});

axiosRetry(httpClient, { 
  retries: 3, 
  retryDelay: (retryCount) => {
    const delay = axiosRetry.exponentialDelay(retryCount);
    const jitter = Math.floor(Math.random() * 100);
    return delay + jitter;
  },
  retryCondition: (error) => {
    return axiosRetry.isNetworkError(error);
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