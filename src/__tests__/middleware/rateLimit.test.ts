import { Request, Response } from 'express';
import { slidingWindowRateLimiter } from '../../middleware/rateLimit';
import { ZeroTrustRequest, TrustLevel } from '../../types';

describe('Rate Limiting Middleware', () => {
  let mockRequest: Partial<ZeroTrustRequest>;
  let mockResponse: Partial<Response>;
  let nextFunction: jest.Mock;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      socket: {
        remoteAddress: '192.168.1.1',
      } as any,
      requestId: 'test-request-id',
      securityContext: {
        requestId: 'test-request-id',
        timestamp: Date.now(),
        clientIp: '192.168.1.1',
        userAgent: 'test-agent',
        authenticated: false,
        authorized: false,
        riskScore: 0,
        trustLevel: 'none',
        policies: [],
      },
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    nextFunction = jest.fn();
  });

  describe('slidingWindowRateLimiter', () => {
    it('should allow requests within limit', () => {
      const limiter = slidingWindowRateLimiter(10, 60000);

      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should block requests exceeding limit', () => {
      const limiter = slidingWindowRateLimiter(2, 60000);

      // First request
      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toHaveBeenCalledTimes(1);

      // Second request
      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toHaveBeenCalledTimes(2);

      // Third request (should be blocked)
      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).toHaveBeenCalledTimes(2); // Not called again
      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            code: 'RATE_LIMIT_ERROR',
          }),
        })
      );
    });

    it('should use different keys for different users', () => {
      const limiter = slidingWindowRateLimiter(1, 60000);

      // First user
      mockRequest.securityContext = {
        ...mockRequest.securityContext!,
        user: {
          id: 'user1',
          email: 'user1@example.com',
          username: 'user1',
          roles: [],
          permissions: [],
          attributes: {},
          sessionId: 'sess_1',
          lastActivity: Date.now(),
          mfaVerified: true,
        },
      };

      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toHaveBeenCalledTimes(1);

      // Second user (different key, should pass)
      mockRequest.securityContext = {
        ...mockRequest.securityContext!,
        user: {
          id: 'user2',
          email: 'user2@example.com',
          username: 'user2',
          roles: [],
          permissions: [],
          attributes: {},
          sessionId: 'sess_2',
          lastActivity: Date.now(),
          mfaVerified: true,
        },
      };

      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toHaveBeenCalledTimes(2);
    });

    it('should include retry-after in response', () => {
      const windowMs = 60000;
      const limiter = slidingWindowRateLimiter(1, windowMs);

      // Exhaust the limit
      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      // Blocked request
      limiter(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            retryAfter: expect.any(Number),
          }),
        })
      );
    });
  });
});
