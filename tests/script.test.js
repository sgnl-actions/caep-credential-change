import { jest } from '@jest/globals';
import { SGNL_USER_AGENT } from '@sgnl-actions/utils';

// Mock dependencies before importing script
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn().mockResolvedValue({
    status: 'success',
    statusCode: 200,
    body: '{"success": true}',
    retryable: false
  })
}));

jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  signSET: jest.fn().mockResolvedValue('mock.jwt.token'),
  getBaseURL: jest.fn((params, context) => params.address || context.environment?.ADDRESS),
  getAuthorizationHeader: jest.fn().mockResolvedValue('Bearer test-token'),
  SGNL_USER_AGENT: 'SGNL-CAEP-Hub/2.0'
}));

const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { signSET, getBaseURL, getAuthorizationHeader } = await import('@sgnl-actions/utils');
const script = await import('../src/script.mjs');

describe('CAEP Credential Change', () => {
  const validParams = {
    audience: 'https://receiver.example.com/',
    subject: '{"format":"account","uri":"acct:test@example.com"}',
    address: 'https://caep.receiver.com/events',
    credential_type: 'password',
    change_type: 'revoke'
  };

  const mockContext = {
    secrets: {
      BEARER_AUTH_TOKEN: 'test-bearer-token'
    },
    environment: {
      ADDRESS: 'https://default.receiver.com/events'
    },
    crypto: {
      signJWT: jest.fn().mockResolvedValue('signed.jwt.token')
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '{"success": true}',
      retryable: false
    });
    signSET.mockResolvedValue('mock.jwt.token');
    getBaseURL.mockImplementation((params, context) => params.address || context.environment?.ADDRESS);
    getAuthorizationHeader.mockResolvedValue('Bearer test-token');
  });

  describe('invoke handler', () => {
    test('should successfully transmit SET with minimal required params', async () => {
      const result = await script.default.invoke(validParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.statusCode).toBe(200);
      expect(result.body).toBe('{"success": true}');
      expect(result.retryable).toBe(false);

      expect(getBaseURL).toHaveBeenCalledWith(validParams, mockContext);
      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          aud: 'https://receiver.example.com/',
          sub_id: { format: 'account', uri: 'acct:test@example.com' },
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              event_timestamp: expect.any(Number),
              credential_type: 'password',
              change_type: 'revoke'
            })
          })
        })
      );

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://caep.receiver.com/events',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'User-Agent': SGNL_USER_AGENT
          })
        })
      );
    });

    test('should include all optional parameters in event payload', async () => {
      const fullParams = {
        ...validParams,
        friendly_name: 'Work Certificate',
        x509_issuer: 'CN=Example CA,O=Example Corp',
        x509_serial: '1234567890ABCDEF',
        fido2_aaguid: '12345678-1234-1234-1234-123456789012',
        initiating_entity: 'admin',
        reason_admin: '{"en": "Certificate revoked by policy", "es": "Certificado revocado por política"}',
        reason_user: '{"en": "Certificate expired", "es": "Certificado expirado"}'
      };

      const result = await script.default.invoke(fullParams, mockContext);

      expect(result.status).toBe('success');
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              friendly_name: 'Work Certificate',
              x509_issuer: 'CN=Example CA,O=Example Corp',
              x509_serial: '1234567890ABCDEF',
              fido2_aaguid: '12345678-1234-1234-1234-123456789012',
              initiating_entity: 'admin',
              reason_admin: { en: "Certificate revoked by policy", es: "Certificado revocado por política" },
              reason_user: { en: "Certificate expired", es: "Certificado expirado" }
            })
          })
        })
      );
    });

    test('should use ADDRESS from environment when address param not provided', async () => {
      const paramsWithoutAddress = {
        ...validParams,
        address: undefined
      };

      await script.default.invoke(paramsWithoutAddress, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(
        expect.objectContaining({ address: undefined }),
        mockContext
      );
    });

    test('should parse subject JSON correctly', async () => {
      await script.default.invoke(validParams, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          sub_id: { format: 'account', uri: 'acct:test@example.com' }
        })
      );
    });

    test('should throw error for invalid subject JSON', async () => {
      const invalidParams = {
        ...validParams,
        subject: 'invalid-json'
      };

      await expect(script.default.invoke(invalidParams, mockContext)).rejects.toThrow(
        'Invalid subject JSON'
      );
    });

    test('should parse i18n reason strings as JSON objects', async () => {
      const paramsWithI18nReason = {
        ...validParams,
        reason_admin: '{"en": "English reason", "es": "Razón en español"}'
      };

      await script.default.invoke(paramsWithI18nReason, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              reason_admin: { en: "English reason", es: "Razón en español" }
            })
          })
        })
      );
    });

    test('should handle plain string reasons', async () => {
      const paramsWithStringReason = {
        ...validParams,
        reason_admin: 'Simple string reason'
      };

      await script.default.invoke(paramsWithStringReason, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              reason_admin: 'Simple string reason'
            })
          })
        })
      );
    });

    test('should handle X.509 credential parameters', async () => {
      const x509Params = {
        ...validParams,
        credential_type: 'x509',
        change_type: 'create',
        x509_issuer: 'CN=Test CA,O=Test Corp',
        x509_serial: 'ABCDEF1234567890'
      };

      const result = await script.default.invoke(x509Params, mockContext);

      expect(result.status).toBe('success');
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              credential_type: 'x509',
              change_type: 'create',
              x509_issuer: 'CN=Test CA,O=Test Corp',
              x509_serial: 'ABCDEF1234567890'
            })
          })
        })
      );
    });

    test('should handle FIDO2 credential parameters', async () => {
      const fido2Params = {
        ...validParams,
        credential_type: 'fido2',
        change_type: 'create',
        fido2_aaguid: '12345678-1234-1234-1234-123456789012'
      };

      const result = await script.default.invoke(fido2Params, mockContext);

      expect(result.status).toBe('success');
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/credential-change': expect.objectContaining({
              credential_type: 'fido2',
              change_type: 'create',
              fido2_aaguid: '12345678-1234-1234-1234-123456789012'
            })
          })
        })
      );
    });

    test('should handle transmitSET failures', async () => {
      transmitSET.mockResolvedValueOnce({
        status: 'failed',
        statusCode: 400,
        body: 'Bad request',
        retryable: false
      });

      const result = await script.default.invoke(validParams, mockContext);

      expect(result.status).toBe('failed');
      expect(result.statusCode).toBe(400);
      expect(result.retryable).toBe(false);
    });
  });

  describe('error handler', () => {
    test('should return retry_requested for retryable errors', async () => {
      const retryableErrors = ['429', '502', '503', '504'];

      for (const code of retryableErrors) {
        const params = {
          error: { message: `Error ${code}: Server error` }
        };

        const result = await script.default.error(params, mockContext);
        expect(result).toEqual({ status: 'retry_requested' });
      }
    });

    test('should re-throw non-retryable errors', async () => {
      const testError = new Error('Invalid credentials');
      const params = {
        error: testError
      };

      await expect(script.default.error(params, mockContext)).rejects.toThrow(testError);
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.default.halt({}, mockContext);

      expect(result).toEqual({ status: 'halted' });
    });
  });
});
