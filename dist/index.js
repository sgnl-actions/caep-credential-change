// SGNL Job Script - Auto-generated bundle
'use strict';

// src/types.ts
var DEFAULT_RETRY_CONFIG = {
  maxAttempts: 3,
  retryableStatuses: [429, 502, 503, 504],
  backoffMs: 1e3,
  maxBackoffMs: 1e4,
  backoffMultiplier: 2
};
var DEFAULT_OPTIONS = {
  timeout: 3e4,
  parseResponse: true,
  validateStatus: (status) => status < 400};
var CONTENT_TYPE_SET = "application/secevent+jwt";
var CONTENT_TYPE_JSON = "application/json";
var DEFAULT_USER_AGENT = "SGNL-Action-Framework/1.0";

// src/errors.ts
var TransmissionError = class _TransmissionError extends Error {
  constructor(message, statusCode, retryable = false, responseBody, responseHeaders) {
    super(message);
    this.statusCode = statusCode;
    this.retryable = retryable;
    this.responseBody = responseBody;
    this.responseHeaders = responseHeaders;
    this.name = "TransmissionError";
    Object.setPrototypeOf(this, _TransmissionError.prototype);
  }
};
var TimeoutError = class _TimeoutError extends TransmissionError {
  constructor(message, timeout) {
    super(`${message} (timeout: ${timeout}ms)`, void 0, true);
    this.name = "TimeoutError";
    Object.setPrototypeOf(this, _TimeoutError.prototype);
  }
};
var NetworkError = class _NetworkError extends TransmissionError {
  constructor(message, cause) {
    super(message, void 0, true);
    this.name = "NetworkError";
    if (cause) {
      this.cause = cause;
    }
    Object.setPrototypeOf(this, _NetworkError.prototype);
  }
};
var ValidationError = class _ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
    Object.setPrototypeOf(this, _ValidationError.prototype);
  }
};

// src/retry.ts
function calculateBackoff(attempt, config, retryAfterMs) {
  if (retryAfterMs !== void 0 && retryAfterMs > 0) {
    return Math.min(retryAfterMs, config.maxBackoffMs);
  }
  const exponentialDelay = config.backoffMs * Math.pow(config.backoffMultiplier, attempt - 1);
  const clampedDelay = Math.min(exponentialDelay, config.maxBackoffMs);
  const jitter = clampedDelay * 0.25;
  const minDelay = clampedDelay - jitter;
  const maxDelay = clampedDelay + jitter;
  return Math.floor(Math.random() * (maxDelay - minDelay) + minDelay);
}
function parseRetryAfter(retryAfterHeader) {
  if (!retryAfterHeader) {
    return void 0;
  }
  const delaySeconds = parseInt(retryAfterHeader, 10);
  if (!isNaN(delaySeconds)) {
    return delaySeconds * 1e3;
  }
  const retryDate = new Date(retryAfterHeader);
  if (!isNaN(retryDate.getTime())) {
    const delayMs = retryDate.getTime() - Date.now();
    return delayMs > 0 ? delayMs : void 0;
  }
  return void 0;
}
function isRetryableStatus(statusCode, retryableStatuses) {
  return retryableStatuses.includes(statusCode);
}
function shouldRetry(statusCode, attempt, config) {
  if (attempt >= config.maxAttempts) {
    return false;
  }
  if (statusCode === void 0) {
    return true;
  }
  return isRetryableStatus(statusCode, config.retryableStatuses);
}
async function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// src/utils.ts
function isValidSET(jwt) {
  if (typeof jwt !== "string") {
    return false;
  }
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return false;
  }
  const base64urlRegex = /^[A-Za-z0-9_-]+$/;
  return parts.every((part) => base64urlRegex.test(part));
}
function normalizeAuthToken(token) {
  if (!token) {
    return void 0;
  }
  if (token.startsWith("Bearer ")) {
    return token;
  }
  return `Bearer ${token}`;
}
function mergeHeaders(defaultHeaders, customHeaders) {
  return {
    ...defaultHeaders,
    ...customHeaders
  };
}
function parseResponseHeaders(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}
async function parseResponseBody(response, parseJson) {
  const text = await response.text();
  if (!parseJson || !text) {
    return text;
  }
  const contentType = response.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

// src/transmitter.ts
async function transmitSET(jwt, url, options = {}) {
  if (!isValidSET(jwt)) {
    throw new ValidationError("Invalid SET format: JWT must be in format header.payload.signature");
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new ValidationError(`Invalid URL: ${url}`);
  }
  const mergedOptions = {
    authToken: options.authToken,
    headers: options.headers || {},
    timeout: options.timeout ?? DEFAULT_OPTIONS.timeout,
    parseResponse: options.parseResponse ?? DEFAULT_OPTIONS.parseResponse,
    validateStatus: options.validateStatus ?? DEFAULT_OPTIONS.validateStatus,
    retry: {
      ...DEFAULT_RETRY_CONFIG,
      ...options.retry || {}
    }
  };
  const baseHeaders = {
    "Content-Type": CONTENT_TYPE_SET,
    Accept: CONTENT_TYPE_JSON,
    "User-Agent": DEFAULT_USER_AGENT
  };
  const authToken = normalizeAuthToken(mergedOptions.authToken);
  if (authToken) {
    baseHeaders["Authorization"] = authToken;
  }
  const headers = mergeHeaders(baseHeaders, mergedOptions.headers);
  let lastError;
  let lastResponse;
  for (let attempt = 1; attempt <= mergedOptions.retry.maxAttempts; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), mergedOptions.timeout);
      try {
        const response = await fetch(parsedUrl.toString(), {
          method: "POST",
          headers,
          body: jwt,
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        lastResponse = response;
        const responseHeaders = parseResponseHeaders(response.headers);
        const responseBody = await parseResponseBody(response, mergedOptions.parseResponse);
        const isSuccess = mergedOptions.validateStatus(response.status);
        if (isSuccess) {
          return {
            status: "success",
            statusCode: response.status,
            body: responseBody,
            headers: responseHeaders
          };
        }
        const canRetry = shouldRetry(response.status, attempt, mergedOptions.retry);
        if (!canRetry) {
          return {
            status: "failed",
            statusCode: response.status,
            body: responseBody,
            headers: responseHeaders,
            error: `HTTP ${response.status}: ${response.statusText}`,
            retryable: mergedOptions.retry.retryableStatuses.includes(response.status)
          };
        }
        const retryAfterMs = parseRetryAfter(responseHeaders["retry-after"]);
        const backoffMs = calculateBackoff(attempt, mergedOptions.retry, retryAfterMs);
        await delay(backoffMs);
      } catch (error) {
        clearTimeout(timeoutId);
        if (error instanceof Error) {
          if (error.name === "AbortError") {
            lastError = new TimeoutError("Request timed out", mergedOptions.timeout);
          } else {
            lastError = new NetworkError(`Network error: ${error.message}`, error);
          }
        } else {
          lastError = new NetworkError("Unknown network error");
        }
        if (!shouldRetry(void 0, attempt, mergedOptions.retry)) {
          throw lastError;
        }
        const backoffMs = calculateBackoff(attempt, mergedOptions.retry);
        await delay(backoffMs);
      }
    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }
  if (lastResponse) {
    const responseHeaders = parseResponseHeaders(lastResponse.headers);
    let responseBody = "";
    try {
      responseBody = await parseResponseBody(lastResponse, mergedOptions.parseResponse);
    } catch {
      responseBody = "";
    }
    return {
      status: "failed",
      statusCode: lastResponse.status,
      body: responseBody,
      headers: responseHeaders,
      error: lastError?.message || `HTTP ${lastResponse.status}: ${lastResponse.statusText}`,
      retryable: true
    };
  }
  throw lastError || new TransmissionError("Failed to transmit SET after all retry attempts", void 0, true);
}

/**
 * SGNL Actions - Authentication Utilities
 *
 * Shared authentication utilities for SGNL actions.
 * Supports: Bearer Token, Basic Auth, OAuth2 Client Credentials, OAuth2 Authorization Code
 */

/**
 * User-Agent header value for all SGNL CAEP Hub requests.
 */
const SGNL_USER_AGENT = 'SGNL-CAEP-Hub/2.0';

/**
 * Get OAuth2 access token using client credentials flow
 * @param {Object} config - OAuth2 configuration
 * @param {string} config.tokenUrl - Token endpoint URL
 * @param {string} config.clientId - Client ID
 * @param {string} config.clientSecret - Client secret
 * @param {string} [config.scope] - OAuth2 scope
 * @param {string} [config.audience] - OAuth2 audience
 * @param {string} [config.authStyle] - Auth style: 'InParams' or 'InHeader' (default)
 * @returns {Promise<string>} Access token
 */
async function getClientCredentialsToken(config) {
  const { tokenUrl, clientId, clientSecret, scope, audience, authStyle } = config;

  if (!tokenUrl || !clientId || !clientSecret) {
    throw new Error('OAuth2 Client Credentials flow requires tokenUrl, clientId, and clientSecret');
  }

  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');

  if (scope) {
    params.append('scope', scope);
  }

  if (audience) {
    params.append('audience', audience);
  }

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
    'User-Agent': SGNL_USER_AGENT
  };

  if (authStyle === 'InParams') {
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
  } else {
    const credentials = btoa(`${clientId}:${clientSecret}`);
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers,
    body: params.toString()
  });

  if (!response.ok) {
    let errorText;
    try {
      const errorData = await response.json();
      errorText = JSON.stringify(errorData);
    } catch {
      errorText = await response.text();
    }
    throw new Error(
      `OAuth2 token request failed: ${response.status} ${response.statusText} - ${errorText}`
    );
  }

  const data = await response.json();

  if (!data.access_token) {
    throw new Error('No access_token in OAuth2 response');
  }

  return data.access_token;
}

/**
 * Get the Authorization header value from context using available auth method.
 * Supports: Bearer Token, Basic Auth, OAuth2 Authorization Code, OAuth2 Client Credentials
 *
 * @param {Object} context - Execution context with environment and secrets
 * @param {Object} context.environment - Environment variables
 * @param {Object} context.secrets - Secret values
 * @returns {Promise<string>} Authorization header value (e.g., "Bearer xxx" or "Basic xxx")
 */
async function getAuthorizationHeader(context) {
  const env = context.environment || {};
  const secrets = context.secrets || {};

  // Method 1: Simple Bearer Token
  if (secrets.BEARER_AUTH_TOKEN) {
    const token = secrets.BEARER_AUTH_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 2: Basic Auth (username + password)
  if (secrets.BASIC_PASSWORD && secrets.BASIC_USERNAME) {
    const credentials = btoa(`${secrets.BASIC_USERNAME}:${secrets.BASIC_PASSWORD}`);
    return `Basic ${credentials}`;
  }

  // Method 3: OAuth2 Authorization Code - use pre-existing access token
  if (secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) {
    const token = secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 4: OAuth2 Client Credentials - fetch new token
  if (secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET) {
    const tokenUrl = env.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL;
    const clientId = env.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID;
    const clientSecret = secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET;

    if (!tokenUrl || !clientId) {
      throw new Error('OAuth2 Client Credentials flow requires TOKEN_URL and CLIENT_ID in env');
    }

    const token = await getClientCredentialsToken({
      tokenUrl,
      clientId,
      clientSecret,
      scope: env.OAUTH2_CLIENT_CREDENTIALS_SCOPE,
      audience: env.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE,
      authStyle: env.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
    });

    return `Bearer ${token}`;
  }

  throw new Error(
    'No authentication configured. Provide one of: ' +
    'BEARER_AUTH_TOKEN, BASIC_USERNAME/BASIC_PASSWORD, ' +
    'OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN, or OAUTH2_CLIENT_CREDENTIALS_*'
  );
}

/**
 * Get the base URL/address for API calls
 * @param {Object} params - Request parameters
 * @param {string} [params.address] - Address from params
 * @param {Object} context - Execution context
 * @returns {string} Base URL
 */
function getBaseURL(params, context) {
  const env = context.environment || {};
  const address = params?.address || env.ADDRESS;

  if (!address) {
    throw new Error('No URL specified. Provide address parameter or ADDRESS environment variable');
  }

  // Remove trailing slash if present
  return address.endsWith('/') ? address.slice(0, -1) : address;
}

/**
 * Security Event Token (SET) Utilities
 *
 * Utilities for building and signing Security Event Tokens according to RFC 8417.
 */

/**
 * Sign a Security Event Token (SET).
 *
 * Reserved claims (iss, iat, jti, exp, nbf) are automatically added during signing
 * and will be filtered from your payload if included.
 *
 * @param {Object} context - The action context with crypto API
 * @param {Object} eventPayload - The SET payload with event-specific claims (aud, sub_id, events, etc.)
 * @returns {Promise<string>} Signed JWT string
 *
 * @example
 * const payload = {
 *   aud: 'https://example.com',
 *   sub_id: { format: 'email', email: 'user@example.com' },
 *   events: {
 *     'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
 *       event_timestamp: Math.floor(Date.now() / 1000)
 *     }
 *   }
 * };
 * const jwt = await signSET(context, payload);
 */
async function signSET(context, eventPayload) {
  // Filter out reserved claims that are set automatically during signing
  const { iss, iat, jti, exp, nbf, ...cleanPayload } = eventPayload;

  if (iss || iat || jti || exp || nbf) {
    console.warn('signSET: Reserved claims (iss, iat, jti, exp, nbf) are set automatically and will be ignored');
  }

  return await context.crypto.signJWT(cleanPayload, { typ: 'secevent+jwt' });
}

// Event type constant
const CREDENTIAL_CHANGE_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';

/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`, { cause: error });
  }
}

/**
 * Parse reason JSON if it's i18n format, otherwise return as string
 */
function parseReason(reasonStr) {
  if (!reasonStr) return reasonStr;

  // Try to parse as JSON for i18n format
  try {
    const parsed = JSON.parse(reasonStr);
    // If it's an object, it's likely i18n format
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not JSON, treat as plain string
  }

  return reasonStr;
}

var script = {
  /**
   * Main execution handler - transmits a CAEP Credential Change event as a Security Event Token
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.subject - Subject identifier JSON (e.g., {"format":"email","email":"user@example.com"})
   * @param {string} params.audience - Intended recipient of the SET (e.g., https://customer.okta.com/)
   * @param {string} params.address - Optional destination URL override (defaults to ADDRESS environment variable)
   * @param {string} params.credential_type - Type of credential that changed (password, x509, fido2, etc.)
   * @param {string} params.change_type - Type of change that occurred (create, revoke, update, delete)
   * @param {string} params.friendly_name - Human-readable name for the credential (optional)
   * @param {string} params.x509_issuer - X.509 certificate issuer (optional)
   * @param {string} params.x509_serial - X.509 certificate serial number (optional)
   * @param {string} params.fido2_aaguid - FIDO2 Authenticator Attestation GUID (optional)
   * @param {string} params.initiating_entity - Entity that initiated the credential change (optional)
   * @param {string} params.reason_admin - Admin-readable reason for the change (optional)
   * @param {string} params.reason_user - User-readable reason for the change (optional)
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {Object} context.environment - Environment configuration
   * @param {string} context.environment.ADDRESS - Default destination URL for the SET transmission
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.BEARER_AUTH_TOKEN
   *
   * @param {string} context.secrets.BASIC_USERNAME
   * @param {string} context.secrets.BASIC_PASSWORD
   *
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @param {Object} context.crypto - Cryptographic operations API
   * @param {Function} context.crypto.signJWT - Function to sign JWTs with server-side keys
   *
   * @returns {Object} Transmission result with status, statusCode, body, and retryable flag
   */
  invoke: async (params, context) => {

    const address = getBaseURL(params, context);
    const authHeader = await getAuthorizationHeader(context);

    // Parse parameters
    const subject = parseSubject(params.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: Math.floor(Date.now() / 1000),
      credential_type: params.credential_type,
      change_type: params.change_type
    };

    // Add optional event claims
    if (params.friendly_name) {
      eventPayload.friendly_name = params.friendly_name;
    }
    if (params.x509_issuer) {
      eventPayload.x509_issuer = params.x509_issuer;
    }
    if (params.x509_serial) {
      eventPayload.x509_serial = params.x509_serial;
    }
    if (params.fido2_aaguid) {
      eventPayload.fido2_aaguid = params.fido2_aaguid;
    }
    if (params.initiating_entity) {
      eventPayload.initiating_entity = params.initiating_entity;
    }
    if (params.reason_admin) {
      eventPayload.reason_admin = parseReason(params.reason_admin);
    }
    if (params.reason_user) {
      eventPayload.reason_user = parseReason(params.reason_user);
    }

    // Build the SET payload (reserved claims will be added during signing)
    const setPayload = {
      aud: params.audience,
      sub_id: subject,  // CAEP 3.0 format
      events: {
        [CREDENTIAL_CHANGE_EVENT]: eventPayload
      }
    };

    const jwt = await signSET(context, setPayload);

    // Transmit the SET
    return await transmitSET(jwt, address, {
      headers: {
        'Authorization': authHeader,
        'User-Agent': SGNL_USER_AGENT
      }
    });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      return { status: 'retry_requested' };
    }

    // Non-retryable error
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  }
};

module.exports = script;
