'use strict';

const axios = require('axios');
const axiosRetry = require('axios-retry').default;

const clientCredentials = require('./clientCredentials');
const jwtBearer = require('./jwtBearer');

const httpClient = axios.create({
  timeout: 10000, 
});

// Configure automatic retries for idempotent network failures
axiosRetry(httpClient, { 
  retries: 3, 
  retryDelay: (retryCount) => axiosRetry.exponentialDelay(retryCount) + Math.floor(Math.random() * 100),
  retryCondition: (error) => {
    // Retry on network errors OR standard transient server errors (5xx)
    return axiosRetry.isNetworkError(error) || (error.response?.status >= 500);
  }
});

const STRATEGIES = {
  'client_credentials': clientCredentials,
  'jwt_bearer': jwtBearer
};

function getStrategy(strategyId) {
  const strategy = STRATEGIES[strategyId];
  if (!strategy) {
    throw new Error(`Unsupported auth strategy: ${strategyId}`);
  }
  return {
    fetchToken: (args) => strategy.fetchToken({ ...args, httpClient })
  };
}

module.exports = { getStrategy };