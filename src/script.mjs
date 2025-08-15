import { createBuilder } from '@sgnl-ai/secevent';
import { createPrivateKey } from 'crypto';

// Event type constant
const CREDENTIAL_CHANGE_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';

/**
 * Transmits a Security Event Token (SET) to the specified endpoint
 * Note: This will be replaced with @sgnl-ai/set-transmitter when available
 */
async function transmitSET(jwt, url, options = {}) {
  const headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/secevent+jwt',
    'User-Agent': options.userAgent || 'SGNL-Action-Framework/1.0'
  };

  if (options.authToken) {
    headers['Authorization'] = options.authToken.startsWith('Bearer ')
      ? options.authToken
      : `Bearer ${options.authToken}`;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: jwt
  });

  const responseBody = await response.text();

  const result = {
    status: response.ok ? 'success' : 'failed',
    statusCode: response.status,
    body: responseBody,
    retryable: false
  };

  // Determine if error is retryable
  if (!response.ok) {
    result.retryable = [429, 502, 503, 504].includes(response.status);
    if (result.retryable) {
      // Throw to trigger framework retry
      throw new Error(`SET transmission failed: ${response.status} ${response.statusText}`);
    }
  }

  return result;
}

/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`);
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
   * Transmit a CAEP Credential Change event
   */
  invoke: async (params, context) => {
    // Validate required parameters
    if (!params.audience) {
      throw new Error('audience is required');
    }
    if (!params.subject) {
      throw new Error('subject is required');
    }
    if (!params.address) {
      throw new Error('address is required');
    }
    if (!params.credentialType) {
      throw new Error('credentialType is required');
    }
    if (!params.changeType) {
      throw new Error('changeType is required');
    }

    // Validate changeType values
    const validChangeTypes = ['create', 'revoke', 'update', 'delete'];
    if (!validChangeTypes.includes(params.changeType)) {
      throw new Error(`changeType must be one of: ${validChangeTypes.join(', ')}`);
    }

    // Get secrets
    const ssfKey = context.secrets?.SSF_KEY;
    const ssfKeyId = context.secrets?.SSF_KEY_ID;
    const authToken = context.secrets?.AUTH_TOKEN;

    if (!ssfKey) {
      throw new Error('SSF_KEY secret is required');
    }
    if (!ssfKeyId) {
      throw new Error('SSF_KEY_ID secret is required');
    }

    // Parse parameters
    const issuer = params.issuer || 'https://sgnl.ai/';
    const signingMethod = params.signingMethod || 'RS256';
    const subject = parseSubject(params.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: params.eventTimestamp || Math.floor(Date.now() / 1000),
      credential_type: params.credentialType,
      change_type: params.changeType
    };

    // Add optional event claims
    if (params.friendlyName) {
      eventPayload.friendly_name = params.friendlyName;
    }
    if (params.x509Issuer) {
      eventPayload.x509_issuer = params.x509Issuer;
    }
    if (params.x509Serial) {
      eventPayload.x509_serial = params.x509Serial;
    }
    if (params.fido2AAGuid) {
      eventPayload.fido2_aaguid = params.fido2AAGuid;
    }
    if (params.initiatingEntity) {
      eventPayload.initiating_entity = params.initiatingEntity;
    }
    if (params.reasonAdmin) {
      eventPayload.reason_admin = parseReason(params.reasonAdmin);
    }
    if (params.reasonUser) {
      eventPayload.reason_user = parseReason(params.reasonUser);
    }

    // Create the SET
    const builder = createBuilder();

    builder
      .withIssuer(issuer)
      .withAudience(params.audience)
      .withIat(Math.floor(Date.now() / 1000))
      .withClaim('sub_id', subject)  // CAEP 3.0 format
      .withEvent(CREDENTIAL_CHANGE_EVENT, eventPayload);

    // Sign the SET
    const privateKeyObject = createPrivateKey(ssfKey);
    const signingKey = {
      key: privateKeyObject,
      alg: signingMethod,
      kid: ssfKeyId
    };

    const { jwt } = await builder.sign(signingKey);

    // Build destination URL
    const url = buildUrl(params.address, params.addressSuffix);

    // Transmit the SET
    return await transmitSET(jwt, url, {
      authToken,
      userAgent: params.userAgent
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