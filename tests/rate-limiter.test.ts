import { RateLimiter } from '../src/services/rate-limiter';
import { CacheService } from '../src/services/cache-service';
import { AuthService } from '../src/services/auth-service';
import { UserRepository } from '../src/repositories/user-repository';
import { PasswordService } from '../src/services/password-service';

jest.mock('../src/services/cache-service');
jest.mock('../src/services/auth-service');
jest.mock('../src/repositories/user-repository');
jest.mock('../src/services/password-service');

describe('Rate Limiter for Login Attempts', () => {
  let rateLimiter: RateLimiter;
  let authService: AuthService;
  let mockCacheService: jest.Mocked<CacheService>;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockPasswordService: jest.Mocked<PasswordService>;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    username: 'testuser',
    passwordHash: '$2b$12$hashedPassword',
    createdAt: new Date(),
    updatedAt: new Date(),
    failedLoginAttempts: 0,
    lockedUntil: null
  };

  beforeEach(() => {
    mockCacheService = new CacheService() as jest.Mocked<CacheService>;
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockPasswordService = new PasswordService() as jest.Mocked<PasswordService>;
    
    rateLimiter = new RateLimiter(mockCacheService);
    authService = new AuthService(mockUserRepository, mockPasswordService, rateLimiter);

    jest.clearAllMocks();
  });

  describe('IP-based Rate Limiting', () => {
    const testIP = '192.168.1.100';

    it('should validate IP address format before processing', async () => {
      const invalidIPs = [
        '999.999.999.999',
        '192.168.1',
        'not-an-ip',
        '',
        'localhost',
        '192.168.1.256'
      ];

      for (const invalidIP of invalidIPs) {
        await expect(rateLimiter.checkLoginAttempt(invalidIP))
          .rejects
          .toThrow('Invalid IP address format');
      }
    });

    it('should accept valid IPv4 and IPv6 addresses', async () => {
      const validIPs = [
        '192.168.1.100',
        '10.0.0.1',
        '127.0.0.1',
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        '::1',
        '2001:db8::1'
      ];

      mockCacheService.get.mockResolvedValue(null);

      for (const validIP of validIPs) {
        const isAllowed = await rateLimiter.checkLoginAttempt(validIP);
        expect(isAllowed).toBe(true);
      }
    });

    it('should allow login attempts within rate limit', async () => {
      mockCacheService.get.mockResolvedValue(null); // No previous attempts

      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(isAllowed).toBe(true);
      expect(mockCacheService.set).toHaveBeenCalledWith(
        `login_attempts:${testIP}`,
        1,
        900 // 15 minutes
      );
    });

    it('should track login attempt count per IP', async () => {
      mockCacheService.get.mockResolvedValue(2); // 2 previous attempts

      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(isAllowed).toBe(true);
      expect(mockCacheService.increment).toHaveBeenCalledWith(`login_attempts:${testIP}`);
    });

    it('should block login attempts after exceeding IP rate limit', async () => {
      mockCacheService.get.mockResolvedValue(10); // Too many attempts

      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(isAllowed).toBe(false);
      expect(mockCacheService.increment).not.toHaveBeenCalled();
    });

    it('should reset IP rate limit after time window', async () => {
      mockCacheService.get.mockResolvedValue(null); // Cache expired

      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(isAllowed).toBe(true);
      expect(mockCacheService.set).toHaveBeenCalledWith(
        `login_attempts:${testIP}`,
        1,
        900
      );
    });

    it('should handle different rate limits for different IPs', async () => {
      const ip1 = '192.168.1.100';
      const ip2 = '192.168.1.101';

      mockCacheService.get.mockImplementation((key) => {
        if (key === `login_attempts:${ip1}`) return Promise.resolve(5);
        if (key === `login_attempts:${ip2}`) return Promise.resolve(2);
        return Promise.resolve(null);
      });

      const allowed1 = await rateLimiter.checkLoginAttempt(ip1);
      const allowed2 = await rateLimiter.checkLoginAttempt(ip2);

      expect(allowed1).toBe(true); // Still under limit
      expect(allowed2).toBe(true); // Different IP, different counter
    });

    it('should apply stricter limits for suspicious IPs', async () => {
      const suspiciousIP = '192.168.1.100';
      mockCacheService.get
        .mockResolvedValueOnce(null) // Not in suspicious list initially
        .mockResolvedValueOnce(3); // 3 attempts

      await rateLimiter.markIPSuspicious(suspiciousIP);
      const isAllowed = await rateLimiter.checkLoginAttempt(suspiciousIP);

      expect(isAllowed).toBe(false); // Should be blocked with stricter limit
    });
  });

  describe('User-based Rate Limiting', () => {
    it('should track failed login attempts per user', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(false);

      const credentials = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      await expect(authService.login(credentials)).rejects.toThrow();

      expect(mockUserRepository.incrementFailedLoginAttempts).toHaveBeenCalledWith('1');
    });

    it('should lock user account after max failed attempts', async () => {
      const lockedUser = {
        ...mockUser,
        failedLoginAttempts: 5,
        lockedUntil: new Date(Date.now() + 30 * 60 * 1000) // Locked for 30 minutes
      };

      mockUserRepository.findByEmail.mockResolvedValue(lockedUser);

      const credentials = {
        email: 'test@example.com',
        password: 'anypassword'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Account temporarily locked due to too many failed login attempts');
    });

    it('should unlock user account after lockout period expires', async () => {
      const expiredLockUser = {
        ...mockUser,
        failedLoginAttempts: 5,
        lockedUntil: new Date(Date.now() - 60 * 1000) // Expired 1 minute ago
      };

      mockUserRepository.findByEmail.mockResolvedValue(expiredLockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);

      const credentials = {
        email: 'test@example.com',
        password: 'correctpassword'
      };

      const result = await authService.login(credentials);

      expect(result).toBeDefined();
      expect(mockUserRepository.resetFailedLoginAttempts).toHaveBeenCalledWith('1');
    });

    it('should implement progressive lockout delays', async () => {
      const testCases = [
        { attempts: 3, expectedDelay: 5 * 60 * 1000 },   // 5 minutes
        { attempts: 4, expectedDelay: 15 * 60 * 1000 },  // 15 minutes
        { attempts: 5, expectedDelay: 30 * 60 * 1000 },  // 30 minutes
        { attempts: 6, expectedDelay: 60 * 60 * 1000 }   // 1 hour
      ];

      for (const testCase of testCases) {
        const delay = rateLimiter.calculateLockoutDelay(testCase.attempts);
        expect(delay).toBe(testCase.expectedDelay);
      }
    });

    it('should reset failed attempts after successful login', async () => {
      const userWithFailedAttempts = {
        ...mockUser,
        failedLoginAttempts: 3
      };

      mockUserRepository.findByEmail.mockResolvedValue(userWithFailedAttempts);
      mockPasswordService.verifyPassword.mockResolvedValue(true);

      const credentials = {
        email: 'test@example.com',
        password: 'correctpassword'
      };

      await authService.login(credentials);

      expect(mockUserRepository.resetFailedLoginAttempts).toHaveBeenCalledWith('1');
    });
  });

  describe('Distributed Rate Limiting', () => {
    it('should synchronize rate limits across multiple servers', async () => {
      const testIP = '192.168.1.100';
      mockCacheService.get.mockResolvedValue(5);

      await rateLimiter.checkLoginAttempt(testIP);

      expect(mockCacheService.get).toHaveBeenCalledWith(`login_attempts:${testIP}`);
      expect(mockCacheService.increment).toHaveBeenCalledWith(`login_attempts:${testIP}`);
    });

    it('should fail-closed when cache service is down', async () => {
      const testIP = '192.168.1.100';
      mockCacheService.get.mockRejectedValue(new Error('Cache service down'));

      // Should implement circuit breaker
      process.env.RATE_LIMITER_FAIL_MODE = 'closed';
      
      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(isAllowed).toBe(false); // Fail closed for security
    });

    it('should implement circuit breaker for cache failures', async () => {
      const testIP = '192.168.1.100';
      
      // Simulate multiple cache failures to open circuit
      mockCacheService.get.mockRejectedValue(new Error('Cache down'));
      
      for (let i = 0; i < 5; i++) {
        try {
          await rateLimiter.checkLoginAttempt(testIP);
        } catch (e) {
          // Expected failures
        }
      }

      // Circuit should be open, failing fast
      const start = Date.now();
      try {
        await rateLimiter.checkLoginAttempt(testIP);
      } catch (e) {
        const duration = Date.now() - start;
        expect(duration).toBeLessThan(10); // Should fail immediately
      }
    });

    it('should use atomic operations for rate limit counters', async () => {
      const testIP = '192.168.1.100';
      mockCacheService.get.mockResolvedValue(3);

      await rateLimiter.checkLoginAttempt(testIP);

      expect(mockCacheService.increment).toHaveBeenCalledWith(`login_attempts:${testIP}`);
    });

    it('should handle clock skew in distributed systems', async () => {
      const testIP = '192.168.1.100';
      const clockSkewMs = 30000; // 30 seconds difference
      
      // Mock time synchronization service
      mockCacheService.getServerTime.mockResolvedValue(Date.now() + clockSkewMs);
      
      const isAllowed = await rateLimiter.checkLoginAttemptWithTimeSync(testIP);
      
      expect(isAllowed).toBe(true);
      expect(mockCacheService.getServerTime).toHaveBeenCalled();
    });

    it('should use Redis-compatible distributed locks', async () => {
      const testIP = '192.168.1.100';
      const lockKey = `rate_limit_lock:${testIP}`;
      
      mockCacheService.acquireLock.mockResolvedValue(true);
      mockCacheService.releaseLock.mockResolvedValue(true);

      await rateLimiter.checkLoginAttemptWithLock(testIP);

      expect(mockCacheService.acquireLock).toHaveBeenCalledWith(lockKey, expect.any(Number));
      expect(mockCacheService.releaseLock).toHaveBeenCalledWith(lockKey);
    });
  });

  describe('Advanced Rate Limiting Features', () => {
    it('should implement sliding window rate limiting', async () => {
      const testIP = '192.168.1.100';
      const currentTime = Date.now();
      
      mockCacheService.get.mockImplementation((key) => {
        if (key === `login_window:${testIP}`) {
          return Promise.resolve({
            attempts: 5,
            windowStart: currentTime - 10 * 60 * 1000 // 10 minutes ago
          });
        }
        return Promise.resolve(null);
      });

      const isAllowed = await rateLimiter.checkSlidingWindowLimit(testIP);

      expect(isAllowed).toBe(true); // Still within window
    });

    it('should implement exponential backoff for repeated violations', async () => {
      const testIP = '192.168.1.100';
      
      mockCacheService.get.mockImplementation((key) => {
        if (key === `violations:${testIP}`) return Promise.resolve(3); // 3 violations
        return Promise.resolve(null);
      });

      const backoffTime = rateLimiter.calculateExponentialBackoff(testIP);
      
      expect(backoffTime).toBe(8 * 60 * 1000); // 2^3 = 8 minutes
    });

    it('should whitelist trusted IPs from rate limiting', async () => {
      const trustedIP = '192.168.1.10';
      rateLimiter.addTrustedIP(trustedIP);

      mockCacheService.get.mockResolvedValue(20); // Would normally be blocked

      const isAllowed = await rateLimiter.checkLoginAttempt(trustedIP);

      expect(isAllowed).toBe(true);
    });

    it('should implement geolocation-based rate limiting', async () => {
      const foreignIP = '1.2.3.4'; // Simulated foreign IP
      
      mockCacheService.get.mockImplementation((key) => {
        if (key.includes('geo:')) return Promise.resolve({ country: 'XX' });
        return Promise.resolve(5); // 5 attempts
      });

      const isAllowed = await rateLimiter.checkLoginAttemptWithGeo(foreignIP);

      expect(isAllowed).toBe(false); // Stricter limits for foreign IPs
    });
  });

  describe('Rate Limiting Integration with Auth Flow', () => {
    it('should check rate limits before processing login', async () => {
      const testIP = '192.168.1.100';
      mockCacheService.get.mockResolvedValue(10); // Exceeds limit

      const credentials = {
        email: 'test@example.com',
        password: 'anypassword',
        clientIP: testIP
      };

      await expect(authService.loginWithRateLimit(credentials))
        .rejects
        .toThrow('Too many login attempts. Please try again later');

      expect(mockUserRepository.findByEmail).not.toHaveBeenCalled();
    });

    it('should apply different limits for different auth endpoints', async () => {
      const limits = {
        login: 5,
        registration: 3,
        passwordReset: 2
      };

      for (const [endpoint, limit] of Object.entries(limits)) {
        const currentLimit = rateLimiter.getLimitForEndpoint(endpoint);
        expect(currentLimit).toBe(limit);
      }
    });

    it('should track successful auth events to adjust limits', async () => {
      const testIP = '192.168.1.100';
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);

      const credentials = {
        email: 'test@example.com',
        password: 'correctpassword',
        clientIP: testIP
      };

      await authService.loginWithRateLimit(credentials);

      expect(mockCacheService.set).toHaveBeenCalledWith(
        `successful_login:${testIP}`,
        1,
        expect.any(Number)
      );
    });
  });

  describe('Security and Monitoring', () => {
    it('should detect and flag brute force attacks', async () => {
      const attackerIP = '192.168.1.100';
      mockCacheService.get.mockResolvedValue(50); // Abnormally high attempts

      const isBruteForce = await rateLimiter.detectBruteForceAttack(attackerIP);

      expect(isBruteForce).toBe(true);
      expect(mockCacheService.set).toHaveBeenCalledWith(
        `brute_force:${attackerIP}`,
        true,
        60 * 60 * 1000 // 1 hour
      );
    });

    it('should log rate limiting events for monitoring', async () => {
      const testIP = '192.168.1.100';
      mockCacheService.get.mockResolvedValue(10);

      await rateLimiter.checkLoginAttempt(testIP);

      expect(mockCacheService.set).toHaveBeenCalledWith(
        `rate_limit_log:${testIP}:${expect.any(String)}`,
        {
          ip: testIP,
          attempts: 10,
          blocked: true,
          timestamp: expect.any(Number)
        },
        24 * 60 * 60 * 1000 // 24 hours
      );
    });

    it('should provide rate limiting statistics', async () => {
      const stats = await rateLimiter.getStatistics();

      expect(stats).toEqual({
        totalAttempts: expect.any(Number),
        blockedAttempts: expect.any(Number),
        uniqueIPs: expect.any(Number),
        topAttackers: expect.any(Array),
        averageAttemptsPerIP: expect.any(Number)
      });
    });

    it('should automatically cleanup expired rate limit data', async () => {
      await rateLimiter.cleanupExpiredData();

      expect(mockCacheService.deletePattern).toHaveBeenCalledWith('login_attempts:*');
      expect(mockCacheService.deleteExpired).toHaveBeenCalled();
    });
  });

  describe('Configuration and Customization', () => {
    it('should load configuration from environment variables', () => {
      process.env.RATE_LIMIT_MAX_ATTEMPTS = '10';
      process.env.RATE_LIMIT_WINDOW_MINUTES = '30';
      process.env.RATE_LIMIT_LOCKOUT_MINUTES = '120';

      const newRateLimiter = new RateLimiter(mockCacheService);
      const config = newRateLimiter.getConfiguration();

      expect(config.maxAttempts).toBe(10);
      expect(config.windowMinutes).toBe(30);
      expect(config.lockoutMinutes).toBe(120);
    });

    it('should use secure defaults when environment variables are missing', () => {
      delete process.env.RATE_LIMIT_MAX_ATTEMPTS;
      delete process.env.RATE_LIMIT_WINDOW_MINUTES;

      const newRateLimiter = new RateLimiter(mockCacheService);
      const config = newRateLimiter.getConfiguration();

      expect(config.maxAttempts).toBe(5); // Secure default
      expect(config.windowMinutes).toBe(15); // Secure default
    });

    it('should allow dynamic rate limit configuration', async () => {
      const newConfig = {
        maxAttempts: 3,
        windowMinutes: 10,
        lockoutMinutes: 60
      };

      rateLimiter.updateConfiguration(newConfig);

      const config = rateLimiter.getConfiguration();
      expect(config).toMatchObject(newConfig);
    });

    it('should support custom rate limiting strategies', async () => {
      const customStrategy = jest.fn().mockReturnValue(false);
      rateLimiter.setCustomStrategy(customStrategy);

      const testIP = '192.168.1.100';
      const isAllowed = await rateLimiter.checkLoginAttempt(testIP);

      expect(customStrategy).toHaveBeenCalledWith(testIP, expect.any(Object));
      expect(isAllowed).toBe(false);
    });

    it('should validate rate limiting configuration', () => {
      const invalidConfig = {
        maxAttempts: -1, // Invalid
        windowMinutes: 0, // Invalid
        lockoutMinutes: 'invalid' // Invalid type
      };

      expect(() => rateLimiter.updateConfiguration(invalidConfig as any))
        .toThrow('Invalid rate limiting configuration');
    });

    it('should reject insecure configuration values', () => {
      const insecureConfigs = [
        { maxAttempts: 1000 }, // Too high
        { windowMinutes: 1 }, // Too short
        { lockoutMinutes: 0.5 } // Too short
      ];

      for (const config of insecureConfigs) {
        expect(() => rateLimiter.updateConfiguration(config))
          .toThrow('Configuration values are not secure');
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle high-volume login attempts efficiently', async () => {
      const promises = Array(1000).fill(null).map((_, i) => 
        rateLimiter.checkLoginAttempt(`192.168.1.${i % 255}`)
      );

      const startTime = Date.now();
      const results = await Promise.all(promises);
      const endTime = Date.now();

      expect(results).toHaveLength(1000);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete in under 5 seconds
    });

    it('should optimize cache operations for rate limiting', async () => {
      const testIP = '192.168.1.100';
      
      await rateLimiter.checkLoginAttempt(testIP);

      expect(mockCacheService.get).toHaveBeenCalledTimes(1);
      expect(mockCacheService.increment).toHaveBeenCalledTimes(1);
    });

    it('should batch rate limit checks for multiple IPs', async () => {
      const ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3'];
      
      mockCacheService.mget.mockResolvedValue([1, 2, 3]);

      const results = await rateLimiter.batchCheckLoginAttempts(ips);

      expect(results).toHaveLength(3);
      expect(mockCacheService.mget).toHaveBeenCalledWith(
        ips.map(ip => `login_attempts:${ip}`)
      );
    });
  });
});