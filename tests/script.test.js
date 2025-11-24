import { jest } from '@jest/globals';

// Mock @sgnl-ai/set-transmitter module
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn().mockResolvedValue({
    status: 'success',
    statusCode: 200,
    body: '{"success":true}',
    retryable: false
  })
}));

// Import after mocking
const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const script = (await import('../src/script.mjs')).default;

describe('CAEP Credential Change Transmitter', () => {
  const mockContext = {
    secrets: {
      BEARER_AUTH_TOKEN: 'Bearer test-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '{"success":true}',
      retryable: false
    });
  });

  describe('invoke', () => {
    const validParams = {
      jwt: 'mock.jwt.token',
      address: 'https://receiver.example.com/events'
    };

    test('should successfully transmit a pre-signed JWT', async () => {
      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"success":true}',
        retryable: false
      });

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          authToken: 'Bearer test-token'
        })
      );
    });

    test('should append address suffix when provided', async () => {
      const params = {
        ...validParams,
        addressSuffix: '/v1/events'
      };

      await script.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events/v1/events',
        expect.any(Object)
      );
    });

    test('should include auth token in request', async () => {
      await script.invoke(validParams, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          authToken: 'Bearer test-token'
        })
      );
    });

    test('should handle auth token without Bearer prefix', async () => {
      const context = {
        secrets: {
          BEARER_AUTH_TOKEN: 'test-token-no-prefix'
        }
      };

      await script.invoke(validParams, context);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          authToken: 'test-token-no-prefix'
        })
      );
    });

    test('should use custom user agent when provided', async () => {
      const params = {
        ...validParams,
        userAgent: 'CustomAgent/1.0'
      };

      await script.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          headers: {
            'User-Agent': 'CustomAgent/1.0'
          }
        })
      );
    });

    test('should throw error for missing jwt', async () => {
      const params = { ...validParams };
      delete params.jwt;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('jwt is required');
    });

    test('should throw error for missing address', async () => {
      const params = { ...validParams };
      delete params.address;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('address is required');
    });

    test('should handle non-retryable HTTP errors', async () => {
      transmitSET.mockResolvedValue({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });
    });

    test('should throw error for retryable HTTP errors', async () => {
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 429 Too Many Requests')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    test('should properly format URL with trailing slash in address', async () => {
      const params = {
        ...validParams,
        address: 'https://receiver.example.com/',
        addressSuffix: '/events'
      };

      await script.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should properly format URL without leading slash in suffix', async () => {
      const params = {
        ...validParams,
        address: 'https://receiver.example.com',
        addressSuffix: 'events'
      };

      await script.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should transmit JWT to correct URL', async () => {
      await script.invoke(validParams, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });
  });

  describe('error handler', () => {
    test('should request retry for 429 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 502 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 503 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 504 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('Authentication failed: 401 Unauthorized')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Authentication failed: 401 Unauthorized');
    });

    test('should re-throw generic errors', async () => {
      const params = {
        error: new Error('Unknown error occurred')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Unknown error occurred');
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, {});

      expect(result).toEqual({ status: 'halted' });
    });
  });
});
