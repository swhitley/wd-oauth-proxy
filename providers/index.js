'use strict';

/**
 * providers/index.js
 *
 * Provider registry.
 *
 * Adding a new OAuth provider requires only:
 *   1. Creating a new file in this directory that exports { meta, fetchToken }.
 *   2. Adding one line to the PROVIDERS map below.
 *
 * The "generic" provider is the default when no ?provider= query param is
 * supplied, or when the supplied value does not match any registered provider.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Provider module contract
 * ─────────────────────────────────────────────────────────────────────────────
 * Every provider module MUST export:
 *
 *   meta        {object}
 *     .id           {string}   Unique identifier (matches the registry key).
 *     .description  {string}   Human-readable description.
 *     .implemented  {boolean}  Set false for stubs; default assumed true.
 *
 *   fetchToken  {async function(params) → object}
 *     params:
 *       targetUrl       {string}  Token endpoint URL.
 *       clientId        {string}  Downstream client_id (always from Secret Manager).
 *       clientSecret    {string}  Downstream client_secret (always from Secret Manager).
 *       scope           {string}  Forwarded from the origin request.
 *       extraBodyFields {object}  Additional fields from the origin request body.
 *     Returns the parsed token response JSON.
 *     Should allow HTTP errors to propagate so index.js can pass them through
 *     verbatim to the caller.
 */

const generic = require('./generic');
const google  = require('./google');

/**
 * Registry map: provider ID → module.
 * Add new providers here as one-liners.
 */
const PROVIDERS = {
  generic: generic,
  google:  google,
  // salesforce: require('./salesforce'),
  // azure:      require('./azure'),
  // okta:       require('./okta'),
};

const DEFAULT_PROVIDER_ID = 'generic';

/**
 * Returns the provider module for the given ID, falling back to the default.
 *
 * @param {string|undefined} providerId
 * @returns {{ meta: object, fetchToken: Function }}
 */
function getProvider(providerId) {
  if (providerId && PROVIDERS[providerId]) {
    return PROVIDERS[providerId];
  }

  if (providerId) {
    console.warn(
      `[Registry] Unknown provider "${providerId}" – falling back to "${DEFAULT_PROVIDER_ID}".`
    );
  }

  return PROVIDERS[DEFAULT_PROVIDER_ID];
}

/**
 * Returns metadata for all registered providers.
 * Used by the GET /providers introspection endpoint.
 *
 * @returns {object[]}
 */
function listProviders() {
  return Object.values(PROVIDERS).map((p) => p.meta);
}

module.exports = { getProvider, listProviders };
