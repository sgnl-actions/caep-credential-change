import { transmitSET } from '@sgnl-ai/set-transmitter';

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

export default {
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