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
 * Build destination URL
 */
function buildUrl(address, suffix) {
  if (!suffix) {
    return address;
  }
  const baseUrl = address.endsWith('/') ? address.slice(0, -1) : address;
  const cleanSuffix = suffix.startsWith('/') ? suffix.slice(1) : suffix;
  return `${baseUrl}/${cleanSuffix}`;
}

var script = {
  /**
   * Transmit a CAEP Session Revoked event
   * @param {Object} params - Input parameters
   * @param {string} params.jwt - Pre-signed JWT Security Event Token
   * @param {string} params.address - Destination URL for the SET transmission
   * @param {string} params.addressSuffix - Optional suffix to append to the address
   * @param {string} params.userAgent - User-Agent header for HTTP requests
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {string} context.secrets.BEARER_AUTH_TOKEN - Bearer token for authenticating with the SET receiver
   *
   * @returns {Promise<Object>} Action result
   */
  invoke: async (params, context) => {
    // Validate required parameters
    if (!params.jwt) {
      throw new Error('jwt is required');
    }
    if (!params.address) {
      throw new Error('address is required');
    }

    // Get secrets
    const authToken = context.secrets?.BEARER_AUTH_TOKEN;

    // Build destination URL
    const url = buildUrl(params.address, params.addressSuffix);

    // Transmit the SET using the library
    return await transmitSET(params.jwt, url, {
      authToken,
      headers: {
        'User-Agent': params.userAgent || 'SGNL-Action-Framework/1.0'
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
