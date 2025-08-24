import jwt from 'jsonwebtoken';
import { TokenService } from '../src/services/token-service';
import { CacheService } from '../src/services/cache-service';

jest.mock('jsonwebtoken');
jest.mock('../src/services/cache-service');

describe('Token Service - Security Enhanced', () => {
  let tokenService: TokenService;
  let mockCacheService: jest.Mocked<CacheService>;
  let mockJwt: jest.Mocked<typeof jwt>;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    mockCacheService = new CacheService() as jest.Mocked<CacheService>;
    mockJwt = jwt as jest.Mocked<typeof jwt>;
    originalEnv = process.env;
    
    tokenService = new TokenService(mockCacheService);
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('JWT Secret Security', () => {
    it('should throw error when JWT_SECRET is missing in production', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.JWT_SECRET;

      expect(() => new TokenService(mockCacheService))
        .toThrow('JWT_SECRET must be set in production environment');
    });

    it('should accept test secret only in development/test environment', () => {
      process.env.NODE_ENV = 'test';
      process.env.JWT_SECRET = 'test-secret';

      expect(() => new TokenService(mockCacheService))
        .not.toThrow();
    });

    it('should enforce minimum secret length in production', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'short';

      expect(() => new TokenService(mockCacheService))
        .toThrow('JWT_SECRET must be at least 32 characters long in production');
    });

    it('should warn about weak secrets in development', () => {
      process.env.NODE_ENV = 'development';
      process.env.JWT_SECRET = 'default-secret-for-testing';
      
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      new TokenService(mockCacheService);

      expect(consoleSpy).toHaveBeenCalledWith(
        'Warning: Using default JWT secret. Set JWT_SECRET environment variable.'
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('Persistent Token Blacklist', () => {
    it('should store invalidated tokens in persistent cache', async () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.validtoken';
      const mockPayload = { userId: '1', exp: Math.floor(Date.now() / 1000) + 3600 };
      
      mockJwt.verify.mockReturnValue(mockPayload as any);

      await tokenService.invalidateToken(token);

      expect(mockCacheService.set).toHaveBeenCalledWith(
        `blacklist:${token}`,
        true,
        3600 * 1000 // TTL based on token expiration
      );
    });

    it('should check blacklist from persistent storage', async () => {
      const token = 'blacklisted-token';
      mockCacheService.get.mockResolvedValue(true);

      const isValid = await tokenService.isTokenBlacklisted(token);

      expect(isValid).toBe(true);
      expect(mockCacheService.get).toHaveBeenCalledWith(`blacklist:${token}`);
    });

    it('should handle cache service failures for blacklist', async () => {
      const token = 'test-token';
      mockCacheService.get.mockRejectedValue(new Error('Cache unavailable'));

      await expect(tokenService.isTokenBlacklisted(token))
        .rejects
        .toThrow('Unable to verify token blacklist status');
    });

    it('should set appropriate TTL for blacklisted tokens', async () => {
      const token = 'expiring-token';
      const expirationTime = Math.floor(Date.now() / 1000) + 1800; // 30 minutes
      const mockPayload = { userId: '1', exp: expirationTime };
      
      mockJwt.verify.mockReturnValue(mockPayload as any);

      await tokenService.invalidateToken(token);

      expect(mockCacheService.set).toHaveBeenCalledWith(
        `blacklist:${token}`,
        true,
        1800 * 1000 // TTL matches token expiration
      );
    });
  });

  describe('JWT Token Validation Enhancement', () => {
    it('should perform comprehensive JWT structure validation', () => {
      const invalidTokens = [
        'not.jwt.token',
        'invalid-jwt',
        'header.payload', // Missing signature
        'too.many.parts.here.invalid',
        '', // Empty token
        'Bearer token-without-jwt-structure'
      ];

      invalidTokens.forEach(token => {
        expect(() => tokenService.validateTokenStructure(token))
          .toThrow('Invalid JWT token structure');
      });
    });

    it('should validate JWT header format', () => {
      const tokenWithInvalidHeader = 'invalidheader.eyJ1c2VySWQiOiIxIn0.signature';
      
      expect(() => tokenService.validateTokenStructure(tokenWithInvalidHeader))
        .toThrow('Invalid JWT header format');
    });

    it('should validate JWT payload format', () => {
      const validHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const invalidPayload = 'invalid-payload';
      const validSignature = 'signature';
      
      const malformedToken = `${validHeader}.${invalidPayload}.${validSignature}`;
      
      expect(() => tokenService.validateTokenStructure(malformedToken))
        .toThrow('Invalid JWT payload format');
    });

    it('should verify token signature before processing', async () => {
      const token = 'valid.jwt.token';
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Invalid signature');
      });

      await expect(tokenService.verifyAccessToken(token))
        .rejects
        .toThrow('Invalid token signature');
    });
  });

  describe('Memory Management', () => {
    it('should cleanup expired blacklisted tokens', async () => {
      await tokenService.cleanupExpiredBlacklistedTokens();

      expect(mockCacheService.deleteExpired).toHaveBeenCalledWith('blacklist:*');
    });

    it('should implement token cleanup scheduling', () => {
      const scheduleCleanupSpy = jest.spyOn(tokenService, 'scheduleCleanup');
      
      new TokenService(mockCacheService);

      expect(scheduleCleanupSpy).toHaveBeenCalled();
    });

    it('should limit blacklist size to prevent memory exhaustion', async () => {
      mockCacheService.count.mockResolvedValue(10000); // Approaching limit

      await expect(tokenService.invalidateToken('new-token'))
        .rejects
        .toThrow('Token blacklist size limit exceeded');
    });
  });

  describe('Token Security Properties', () => {
    it('should generate cryptographically secure refresh tokens', () => {
      const refreshToken = tokenService.generateRefreshToken('user123');
      
      expect(refreshToken).toMatch(/^[A-Za-z0-9+/]{43}=$/); // Base64 encoded 32 bytes
      expect(refreshToken.length).toBe(44);
    });

    it('should use different secrets for access and refresh tokens', () => {
      process.env.JWT_ACCESS_SECRET = 'access-secret-key';
      process.env.JWT_REFRESH_SECRET = 'refresh-secret-key';
      
      const newService = new TokenService(mockCacheService);
      
      expect(newService.getAccessTokenSecret()).not.toBe(newService.getRefreshTokenSecret());
    });

    it('should implement token rotation for refresh tokens', async () => {
      const oldRefreshToken = 'old-refresh-token';
      const userId = 'user123';
      
      mockJwt.verify.mockReturnValue({ userId, type: 'refresh' });
      mockCacheService.get.mockResolvedValue(null); // Not blacklisted

      const result = await tokenService.rotateRefreshToken(oldRefreshToken);

      expect(result.newRefreshToken).toBeDefined();
      expect(result.newAccessToken).toBeDefined();
      expect(mockCacheService.set).toHaveBeenCalledWith(
        `blacklist:${oldRefreshToken}`,
        true,
        expect.any(Number)
      );
    });
  });

  describe('Concurrent Token Operations', () => {
    it('should handle concurrent invalidation requests atomically', async () => {
      const token = 'concurrent-token';
      const mockPayload = { userId: '1', exp: Math.floor(Date.now() / 1000) + 3600 };
      
      mockJwt.verify.mockReturnValue(mockPayload as any);
      mockCacheService.setNX.mockResolvedValue(true); // Atomic set if not exists

      const promises = Array(10).fill(null).map(() => 
        tokenService.invalidateToken(token)
      );

      await Promise.all(promises);

      expect(mockCacheService.setNX).toHaveBeenCalledWith(
        `blacklist:${token}`,
        true,
        expect.any(Number)
      );
    });

    it('should prevent race conditions in token validation', async () => {
      const token = 'race-condition-token';
      mockCacheService.get.mockImplementation(() => 
        new Promise(resolve => setTimeout(() => resolve(null), 50))
      );

      const promises = Array(5).fill(null).map(() => 
        tokenService.isTokenBlacklisted(token)
      );

      const results = await Promise.all(promises);
      
      expect(results.every(result => result === false)).toBe(true);
      expect(mockCacheService.get).toHaveBeenCalledTimes(5);
    });
  });

  describe('Error Handling and Resilience', () => {
    it('should handle JWT library errors gracefully', async () => {
      const token = 'problematic-token';
      mockJwt.verify.mockImplementation(() => {
        throw new Error('JWT library internal error');
      });

      await expect(tokenService.verifyAccessToken(token))
        .rejects
        .toThrow('Token verification failed');
    });

    it('should implement circuit breaker for cache failures', async () => {
      // Simulate cache failures
      mockCacheService.get.mockRejectedValue(new Error('Cache down'));
      
      // After multiple failures, should open circuit
      for (let i = 0; i < 5; i++) {
        try {
          await tokenService.isTokenBlacklisted('test-token');
        } catch (e) {
          // Expected failures
        }
      }

      // Circuit should be open, failing fast
      const start = Date.now();
      try {
        await tokenService.isTokenBlacklisted('another-token');
      } catch (e) {
        const duration = Date.now() - start;
        expect(duration).toBeLessThan(10); // Should fail immediately
      }
    });

    it('should log security events', async () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      
      await tokenService.invalidateToken('suspicious-token');

      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'token_invalidated',
          tokenId: expect.any(String),
          timestamp: expect.any(Number)
        })
      );
      
      logSpy.mockRestore();
    });
  });

  describe('Configuration and Environment', () => {
    it('should validate configuration on startup', () => {
      process.env.JWT_SECRET = '';
      process.env.JWT_EXPIRATION = 'invalid';

      expect(() => new TokenService(mockCacheService))
        .toThrow('Invalid token service configuration');
    });

    it('should use environment-specific defaults', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'production-secret-key-with-sufficient-length';
      
      const service = new TokenService(mockCacheService);
      
      expect(service.getDefaultExpiration()).toBe(15 * 60); // 15 minutes in production
    });

    it('should support token lifetime configuration', () => {
      process.env.JWT_ACCESS_EXPIRATION = '600'; // 10 minutes
      process.env.JWT_REFRESH_EXPIRATION = '86400'; // 24 hours
      
      const service = new TokenService(mockCacheService);
      
      expect(service.getAccessTokenLifetime()).toBe(600);
      expect(service.getRefreshTokenLifetime()).toBe(86400);
    });
  });
});