import { transmitSET } from '@sgnl-ai/set-transmitter';
import { signSET, getBaseURL, getAuthorizationHeader, SGNL_USER_AGENT } from '@sgnl-actions/utils';

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

export default {
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
