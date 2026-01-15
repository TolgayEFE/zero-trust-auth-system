import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { jwtAuthMiddleware, blacklistToken, requireRoles } from '../../middleware/jwt';
import { ZeroTrustRequest, SecurityContext, TrustLevel } from '../../types';
import { config } from '../../config';

// Mock config
jest.mock('../../config', () => ({
  config: {
    jwt: {
      secret: 'test-jwt-secret-that-is-at-least-32-characters-long',
      expiration: '15m',
      refreshExpiration: '7d',
      issuer: 'zero-trust-gateway',
      audience: 'zero-trust-services',
      algorithm: 'HS256',
    },
  },
}));

describe('JWT Authentication Middleware', () => {
  let mockRequest: Partial<ZeroTrustRequest>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      requestId: 'test-request-id',
      securityContext: {
        requestId: 'test-request-id',
        timestamp: Date.now(),
        clientIp: '127.0.0.1',
        userAgent: 'test-agent',
        authenticated: false,
        authorized: false,
        riskScore: 0,
        trustLevel: 'none',
        policies: [],
      } as SecurityContext,
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    nextFunction = jest.fn();
  });

  const createValidToken = (payload: Record<string, unknown> = {}): string => {
    return jwt.sign(
      {
        sub: 'user123',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read:own'],
        sessionId: 'sess_123',
        mfaVerified: true,
        ...payload,
      },
      config.jwt.secret,
      {
        expiresIn: '15m',
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }
    );
  };

  describe('jwtAuthMiddleware', () => {
    it('should reject request without authorization header', () => {
      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            code: 'AUTHENTICATION_ERROR',
          }),
        })
      );
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject request with invalid authorization scheme', () => {
      mockRequest.headers = {
        authorization: 'Basic dGVzdDp0ZXN0',
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject request with malformed authorization header', () => {
      mockRequest.headers = {
        authorization: 'Bearer',
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject request with invalid token', () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token',
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject expired token', () => {
      const expiredToken = jwt.sign(
        {
          sub: 'user123',
          email: 'test@example.com',
          username: 'testuser',
          roles: ['user'],
          permissions: ['read:own'],
          sessionId: 'sess_123',
        },
        config.jwt.secret,
        {
          expiresIn: '0s',
          issuer: config.jwt.issuer,
          audience: config.jwt.audience,
        }
      );

      mockRequest.headers = {
        authorization: `Bearer ${expiredToken}`,
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            message: 'Token expired',
          }),
        })
      );
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject blacklisted token', () => {
      const token = createValidToken();
      blacklistToken(token);

      mockRequest.headers = {
        authorization: `Bearer ${token}`,
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should accept valid token and update security context', () => {
      const token = createValidToken();

      mockRequest.headers = {
        authorization: `Bearer ${token}`,
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).toHaveBeenCalled();
      expect(mockRequest.securityContext?.authenticated).toBe(true);
      expect(mockRequest.securityContext?.user?.id).toBe('user123');
      expect(mockRequest.securityContext?.user?.email).toBe('test@example.com');
      expect(mockRequest.securityContext?.user?.username).toBe('testuser');
      expect(mockRequest.securityContext?.user?.roles).toEqual(['user']);
    });

    it('should reject token with wrong issuer', () => {
      const invalidToken = jwt.sign(
        {
          sub: 'user123',
          email: 'test@example.com',
          username: 'testuser',
          roles: ['user'],
          permissions: ['read:own'],
          sessionId: 'sess_123',
        },
        config.jwt.secret,
        {
          expiresIn: '15m',
          issuer: 'wrong-issuer',
          audience: config.jwt.audience,
        }
      );

      mockRequest.headers = {
        authorization: `Bearer ${invalidToken}`,
      };

      jwtAuthMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });

  describe('requireRoles', () => {
    it('should allow user with required role', () => {
      mockRequest.securityContext = {
        ...mockRequest.securityContext!,
        user: {
          id: 'user123',
          email: 'test@example.com',
          username: 'testuser',
          roles: ['admin'],
          permissions: [],
          attributes: {},
          sessionId: 'sess_123',
          lastActivity: Date.now(),
          mfaVerified: true,
        },
      };

      const middleware = requireRoles('admin');
      middleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).toHaveBeenCalled();
    });

    it('should reject user without required role', () => {
      mockRequest.securityContext = {
        ...mockRequest.securityContext!,
        user: {
          id: 'user123',
          email: 'test@example.com',
          username: 'testuser',
          roles: ['user'],
          permissions: [],
          attributes: {},
          sessionId: 'sess_123',
          lastActivity: Date.now(),
          mfaVerified: true,
        },
      };

      const middleware = requireRoles('admin');
      middleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject unauthenticated user', () => {
      mockRequest.securityContext = {
        ...mockRequest.securityContext!,
        user: undefined,
      };

      const middleware = requireRoles('admin');
      middleware(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });
});
