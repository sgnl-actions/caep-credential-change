import { jest } from '@jest/globals';
import script from '../src/script.mjs';

// Mock fetch globally
globalThis.fetch = jest.fn();

describe('CAEP Credential Change', () => {
  const validParams = {
    audience: 'https://receiver.example.com/',
    subject: '{"format":"account","uri":"acct:test@example.com"}',
    address: 'https://caep.receiver.com/events',
    credentialType: 'password',
    changeType: 'revoke'
  };

  const mockContext = {
    secrets: {
      SSF_KEY: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVP1FMSuoWHsTt
qnJ4BcVCADc3lFpnZjLsRiRs9WvqqdbYYrf0zqOrHoqbLMMGg601pnf20Y6e7xim
8KK7l2L7kVvfkIGPnDqwQWlkjEx5pBLQRz1WQdnz2hr6IpfZO4Z8zyjnySv/K5LU
nlJrzGdyHWmDKQAU9w4E2+zFmtcuwTM8mWJQoy3CBuwQ8/r+OsycRuxw0GvEA+yp
jm4PScbMFL+g8f2yPm1ACucrc/ogCSTv+yjbXJcdy95pgpOu/IrcbbyPJLE8+9Nt
eEr2gmNU8CzOHfflUJfAE7FHrCMJA593mKAlaULE2b53zAEVxuCSaKGiOJQ2ELhl
jRh+MeijAgMBAAECggEADDkw195E2MXxXAO7N1BFrRembhNk6hYJMqe2AQSCr6f0
VCmVpmOsLO4l7PqYCHcNXxkAt0LHewXbD4Ui1tlZvn/TtfY4XkIt3lSlJJqHAulo
rw0+nUtsZdfloLnnlN+Wrq8qyv0DcPUpI+fJmVGW4VY+V4Mqogzv5X77n92EJSyG
lMtLJCkB3AAP9ul5S4KbPs/GgMrLGKlMbfD8mTeZW0h5Bvgm34l/TLWLbnPQHtmF
HeMzYuwZjljpKNHfWc2L22soYvpcFS9CKzEozXa8DGkvEM9ZI8o1tHvFBOiFzUDn
Ydwl6dCm6m7PjnQ9GvR09UzPxTBLXwuKES/m28f75QKBgQDJhqOxW94it6pNtBKc
rd3+U1DqmBY4/pJ2R5y6I5vR9fMnG7s+9tXMrP7kV5bDXLJHVX5KKTB9ydO8PyA1
19fE3ftlIfDeZ1B+zTvwDsMyplEfOIqXMlKPViS1VvVU46HkHlwLB+nGyDSLtZPR
XQlzkmhFB6wGWaTBftYB+3qb1wKBgQC9lw9ISvhovGKVBBOCXycKvdvtW80phUyX
HQeXuTWYjaTP8a+0qNZ/zGgsgz+zEiXQQODreORR309p+3/DFl4YMm7SR/D6Fcc3
CKvFBQFv6wPnc+5tyOQoq32jXPp/XY5X8NUAPR3FbqwE40gQ2qXSOB/61H6l+m0C
JXVvMJHgFQKBgHKqo3WFWk3Sx5pS/cwcuhW9/mqdgveHEnsuoCThogXDtkjoZJCd
DmXZgWcX13btxZsFMEiuSyMntcyE9qTsXZ9s12BiAZXqn0inKpWbMMIfFEV5fJIv
Vf6s+1IbWpiktTcBd0nnhMNQo2VjOeqEz53tDltI1D8AvthCfS6/krIdAoGAQ4FQ
8LW5A1noZBTCeY410Y5Oi5I/V8RdxASTGoPYwIvWni/5FwNy9Kgsg4TsHm+cxS0E
qPMvoLM5jIv/LtB9CnKSoQ76j6FHgKH2vz0MCPSOPFA8Gh0ImC6PmqZVjxoZv9hB
j0cznYPNfiQLGe0wU8ymHmKhAapMPBJoYQHTPw0CgYAPyVbhsQf1M0Qu0ROxhbzY
qYeWeRz1GNGMqCHC1r1NFHuv0qvX2g7kVh2E3+OGu6Jr1TgzTXZMyFVRiPMokPQL
uMTJPqjqASAE4C6akEErJM2yY+3pVy+OHxd5ewZskchqY3YOI26uL9tEW3rzLp18
lUIPAweNrL/7ssEesKGGEw==
-----END PRIVATE KEY-----`,
      SSF_KEY_ID: 'test-key-id',
      AUTH_TOKEN: 'test-bearer-token'
    }
  };

  beforeEach(() => {
    globalThis.fetch.mockClear();
  });

  describe('invoke handler', () => {
    test('should successfully transmit SET with minimal required params', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{"success": true}')
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.statusCode).toBe(200);
      expect(result.body).toBe('{"success": true}');
      expect(result.retryable).toBe(false);

      expect(globalThis.fetch).toHaveBeenCalledWith(
        'https://caep.receiver.com/events',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Accept': 'application/json',
            'Content-Type': 'application/secevent+jwt',
            'Authorization': 'Bearer test-bearer-token',
            'User-Agent': 'SGNL-Action-Framework/1.0'
          })
        })
      );
    });

    test('should include all optional parameters in event payload', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const fullParams = {
        ...validParams,
        friendlyName: 'Work Certificate',
        x509Issuer: 'CN=Example CA,O=Example Corp',
        x509Serial: '1234567890ABCDEF',
        fido2AAGuid: '12345678-1234-1234-1234-123456789012',
        initiatingEntity: 'admin',
        reasonAdmin: '{"en": "Certificate revoked by policy", "es": "Certificado revocado por política"}',
        reasonUser: '{"en": "Certificate expired", "es": "Certificado expirado"}',
        eventTimestamp: 1609459200,
        addressSuffix: '/caep',
        userAgent: 'Custom-Agent/1.0'
      };

      const result = await script.invoke(fullParams, mockContext);

      expect(result.status).toBe('success');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        'https://caep.receiver.com/events/caep',
        expect.objectContaining({
          headers: expect.objectContaining({
            'User-Agent': 'Custom-Agent/1.0'
          })
        })
      );
    });

    test('should validate required parameters', async () => {
      const testCases = [
        { params: { ...validParams, audience: undefined }, error: 'audience is required' },
        { params: { ...validParams, subject: undefined }, error: 'subject is required' },
        { params: { ...validParams, address: undefined }, error: 'address is required' },
        { params: { ...validParams, credentialType: undefined }, error: 'credentialType is required' },
        { params: { ...validParams, changeType: undefined }, error: 'changeType is required' }
      ];

      for (const { params, error } of testCases) {
        await expect(script.invoke(params, mockContext)).rejects.toThrow(error);
      }
    });

    test('should validate changeType values', async () => {
      const invalidParams = {
        ...validParams,
        changeType: 'invalid'
      };

      await expect(script.invoke(invalidParams, mockContext)).rejects.toThrow(
        'changeType must be one of: create, revoke, update, delete'
      );
    });

    test('should accept all valid changeType values', async () => {
      const validChangeTypes = ['create', 'revoke', 'update', 'delete'];

      for (const changeType of validChangeTypes) {
        globalThis.fetch.mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve('OK')
        });

        const params = { ...validParams, changeType };
        const result = await script.invoke(params, mockContext);
        expect(result.status).toBe('success');
      }
    });

    test('should validate subject JSON format', async () => {
      const invalidParams = {
        ...validParams,
        subject: 'invalid-json'
      };

      await expect(script.invoke(invalidParams, mockContext)).rejects.toThrow(
        'Invalid subject JSON'
      );
    });

    test('should require SSF_KEY secret', async () => {
      const contextWithoutKey = {
        secrets: {
          SSF_KEY_ID: 'test-key-id'
        }
      };

      await expect(script.invoke(validParams, contextWithoutKey)).rejects.toThrow(
        'SSF_KEY secret is required'
      );
    });

    test('should require SSF_KEY_ID secret', async () => {
      const contextWithoutKeyId = {
        secrets: {
          SSF_KEY: mockContext.secrets.SSF_KEY
        }
      };

      await expect(script.invoke(validParams, contextWithoutKeyId)).rejects.toThrow(
        'SSF_KEY_ID secret is required'
      );
    });

    test('should handle URL building with suffix', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const paramsWithSuffix = {
        ...validParams,
        addressSuffix: '/caep/events'
      };

      await script.invoke(paramsWithSuffix, mockContext);

      expect(globalThis.fetch).toHaveBeenCalledWith(
        'https://caep.receiver.com/events/caep/events',
        expect.any(Object)
      );
    });

    test('should handle Bearer token prefix', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const contextWithBearerToken = {
        secrets: {
          ...mockContext.secrets,
          AUTH_TOKEN: 'Bearer already-prefixed-token'
        }
      };

      await script.invoke(validParams, contextWithBearerToken);

      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer already-prefixed-token'
          })
        })
      );
    });

    test('should parse i18n reason strings as JSON', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const paramsWithI18nReason = {
        ...validParams,
        reasonAdmin: '{"en": "English reason", "es": "Razón en español"}'
      };

      const result = await script.invoke(paramsWithI18nReason, mockContext);
      expect(result.status).toBe('success');
    });

    test('should handle plain string reasons', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const paramsWithStringReason = {
        ...validParams,
        reasonAdmin: 'Simple string reason'
      };

      const result = await script.invoke(paramsWithStringReason, mockContext);
      expect(result.status).toBe('success');
    });

    test('should throw for retryable HTTP errors', async () => {
      const retryableCodes = [429, 502, 503, 504];

      for (const code of retryableCodes) {
        globalThis.fetch.mockResolvedValueOnce({
          ok: false,
          status: code,
          statusText: 'Error',
          text: () => Promise.resolve('Error message')
        });

        await expect(script.invoke(validParams, mockContext)).rejects.toThrow(
          `SET transmission failed: ${code} Error`
        );
      }
    });

    test('should not throw for non-retryable HTTP errors', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: () => Promise.resolve('Bad request')
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result.status).toBe('failed');
      expect(result.statusCode).toBe(400);
      expect(result.retryable).toBe(false);
    });

    test('should handle X.509 credential parameters', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const x509Params = {
        ...validParams,
        credentialType: 'x509',
        changeType: 'create',
        x509Issuer: 'CN=Test CA,O=Test Corp',
        x509Serial: 'ABCDEF1234567890'
      };

      const result = await script.invoke(x509Params, mockContext);
      expect(result.status).toBe('success');
    });

    test('should handle FIDO2 credential parameters', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve('OK')
      });

      const fido2Params = {
        ...validParams,
        credentialType: 'fido2',
        changeType: 'create',
        fido2AAGuid: '12345678-1234-1234-1234-123456789012'
      };

      const result = await script.invoke(fido2Params, mockContext);
      expect(result.status).toBe('success');
    });
  });

  describe('error handler', () => {
    test('should return retry_requested for retryable errors', async () => {
      const retryableErrors = ['429', '502', '503', '504'];

      for (const code of retryableErrors) {
        const params = {
          error: { message: `Error ${code}: Server error` }
        };

        const result = await script.error(params, mockContext);
        expect(result).toEqual({ status: 'retry_requested' });
      }
    });

    test('should re-throw non-retryable errors', async () => {
      const testError = new Error('Invalid credentials');
      const params = {
        error: testError
      };

      await expect(script.error(params, mockContext)).rejects.toThrow(testError);
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, mockContext);

      expect(result).toEqual({ status: 'halted' });
    });
  });
});