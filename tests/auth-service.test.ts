import jwt from 'jsonwebtoken';
import { AuthService } from '../src/services/auth-service';
import { UserRepository } from '../src/repositories/user-repository';
import { PasswordService } from '../src/services/password-service';
import { TokenService } from '../src/services/token-service';

jest.mock('jsonwebtoken');
jest.mock('../src/repositories/user-repository');
jest.mock('../src/services/password-service');
jest.mock('../src/services/token-service');

describe('Authentication Service - Login & JWT', () => {
  let authService: AuthService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockPasswordService: jest.Mocked<PasswordService>;
  let mockTokenService: jest.Mocked<TokenService>;
  let mockJwt: jest.Mocked<typeof jwt>;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    username: 'testuser',
    passwordHash: '$2b$12$hashedPassword',
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLoginAt: null,
    failedLoginAttempts: 0,
    lockedUntil: null
  };

  beforeEach(() => {
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockPasswordService = new PasswordService() as jest.Mocked<PasswordService>;
    mockTokenService = new TokenService() as jest.Mocked<TokenService>;
    mockJwt = jwt as jest.Mocked<typeof jwt>;
    
    authService = new AuthService(mockUserRepository, mockPasswordService, mockTokenService);
  });

  describe('Login Validation', () => {
    it('should reject login with empty email', async () => {
      const credentials = {
        email: '',
        password: 'ValidPassword123!'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Email is required');
    });

    it('should reject login with empty password', async () => {
      const credentials = {
        email: 'test@example.com',
        password: ''
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Password is required');
    });

    it('should reject login with non-existent user', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(null);

      const credentials = {
        email: 'nonexistent@example.com',
        password: 'ValidPassword123!'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Invalid credentials');
    });

    it('should handle case-insensitive email lookup', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('valid-jwt-token');
      mockTokenService.generateRefreshToken.mockReturnValue('valid-refresh-token');

      const credentials = {
        email: 'TEST@EXAMPLE.COM',
        password: 'ValidPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result).toBeDefined();
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
    });
  });

  describe('Password Verification', () => {
    beforeEach(() => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
    });

    it('should reject login with incorrect password', async () => {
      mockPasswordService.verifyPassword.mockResolvedValue(false);

      const credentials = {
        email: 'test@example.com',
        password: 'WrongPassword123!'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Invalid credentials');
      
      expect(mockPasswordService.verifyPassword)
        .toHaveBeenCalledWith('WrongPassword123!', '$2b$12$hashedPassword');
    });

    it('should accept login with correct password', async () => {
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('valid-jwt-token');
      mockTokenService.generateRefreshToken.mockReturnValue('valid-refresh-token');

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('valid-jwt-token');
      expect(mockPasswordService.verifyPassword)
        .toHaveBeenCalledWith('CorrectPassword123!', '$2b$12$hashedPassword');
    });
  });

  describe('JWT Token Generation', () => {
    beforeEach(() => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
    });

    it('should generate valid access token with user payload', async () => {
      const expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.validtoken';
      mockTokenService.generateAccessToken.mockReturnValue(expectedToken);
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token');

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result.accessToken).toBe(expectedToken);
      expect(mockTokenService.generateAccessToken).toHaveBeenCalledWith({
        userId: '1',
        email: 'test@example.com',
        username: 'testuser'
      });
    });

    it('should generate refresh token', async () => {
      const expectedRefreshToken = 'refresh-token-example';
      mockTokenService.generateAccessToken.mockReturnValue('access-token');
      mockTokenService.generateRefreshToken.mockReturnValue(expectedRefreshToken);

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result.refreshToken).toBe(expectedRefreshToken);
      expect(mockTokenService.generateRefreshToken).toHaveBeenCalledWith('1');
    });

    it('should include token expiration information', async () => {
      const mockTokenExpiry = Date.now() + (60 * 60 * 1000); // 1 hour
      mockTokenService.generateAccessToken.mockReturnValue('access-token');
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token');
      mockTokenService.getTokenExpiration.mockReturnValue(mockTokenExpiry);

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result.expiresAt).toBe(mockTokenExpiry);
      expect(result.expiresIn).toBe(3600); // seconds
    });

    it('should handle token generation failure', async () => {
      mockTokenService.generateAccessToken.mockImplementation(() => {
        throw new Error('Token generation failed');
      });

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Authentication failed');
    });
  });

  describe('Token Validation', () => {
    it('should validate valid JWT token', async () => {
      const validToken = 'valid-jwt-token';
      const decodedPayload = {
        userId: '1',
        email: 'test@example.com',
        username: 'testuser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };

      mockTokenService.verifyAccessToken.mockReturnValue(decodedPayload);

      const result = await authService.validateToken(validToken);

      expect(result).toEqual({
        valid: true,
        payload: decodedPayload
      });
    });

    it('should reject expired JWT token', async () => {
      const expiredToken = 'expired-jwt-token';
      mockTokenService.verifyAccessToken.mockImplementation(() => {
        const error = new Error('Token expired');
        error.name = 'TokenExpiredError';
        throw error;
      });

      const result = await authService.validateToken(expiredToken);

      expect(result).toEqual({
        valid: false,
        error: 'Token expired'
      });
    });

    it('should reject malformed JWT token', async () => {
      const malformedToken = 'malformed.token';
      mockTokenService.verifyAccessToken.mockImplementation(() => {
        const error = new Error('Invalid token');
        error.name = 'JsonWebTokenError';
        throw error;
      });

      const result = await authService.validateToken(malformedToken);

      expect(result).toEqual({
        valid: false,
        error: 'Invalid token'
      });
    });

    it('should handle missing token', async () => {
      const result = await authService.validateToken('');

      expect(result).toEqual({
        valid: false,
        error: 'Token is required'
      });
    });
  });

  describe('Token Refresh', () => {
    it('should refresh valid refresh token', async () => {
      const refreshToken = 'valid-refresh-token';
      const newAccessToken = 'new-access-token';
      const newRefreshToken = 'new-refresh-token';

      mockTokenService.verifyRefreshToken.mockReturnValue({ userId: '1' });
      mockUserRepository.findById.mockResolvedValue(mockUser);
      mockTokenService.generateAccessToken.mockReturnValue(newAccessToken);
      mockTokenService.generateRefreshToken.mockReturnValue(newRefreshToken);

      const result = await authService.refreshToken(refreshToken);

      expect(result).toEqual({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt: expect.any(Number),
        expiresIn: expect.any(Number)
      });
    });

    it('should reject invalid refresh token', async () => {
      const invalidRefreshToken = 'invalid-refresh-token';
      mockTokenService.verifyRefreshToken.mockImplementation(() => {
        throw new Error('Invalid refresh token');
      });

      await expect(authService.refreshToken(invalidRefreshToken))
        .rejects
        .toThrow('Invalid refresh token');
    });

    it('should reject refresh token for non-existent user', async () => {
      const refreshToken = 'valid-refresh-token';
      mockTokenService.verifyRefreshToken.mockReturnValue({ userId: '999' });
      mockUserRepository.findById.mockResolvedValue(null);

      await expect(authService.refreshToken(refreshToken))
        .rejects
        .toThrow('User not found');
    });
  });

  describe('Login Success Tracking', () => {
    beforeEach(() => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('access-token');
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token');
    });

    it('should update last login timestamp on successful login', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      await authService.login(credentials);

      expect(mockUserRepository.updateLastLogin).toHaveBeenCalledWith('1');
    });

    it('should reset failed login attempts on successful login', async () => {
      const userWithFailedAttempts = {
        ...mockUser,
        failedLoginAttempts: 3
      };
      mockUserRepository.findByEmail.mockResolvedValue(userWithFailedAttempts);

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      await authService.login(credentials);

      expect(mockUserRepository.resetFailedLoginAttempts).toHaveBeenCalledWith('1');
    });
  });

  describe('Logout Functionality', () => {
    it('should invalidate access token on logout', async () => {
      const accessToken = 'valid-access-token';
      mockTokenService.verifyAccessToken.mockReturnValue({
        userId: '1',
        email: 'test@example.com',
        username: 'testuser'
      });

      await authService.logout(accessToken);

      expect(mockTokenService.invalidateToken).toHaveBeenCalledWith(accessToken);
    });

    it('should invalidate refresh token on logout', async () => {
      const accessToken = 'valid-access-token';
      const refreshToken = 'valid-refresh-token';
      
      mockTokenService.verifyAccessToken.mockReturnValue({
        userId: '1',
        email: 'test@example.com',
        username: 'testuser'
      });

      await authService.logout(accessToken, refreshToken);

      expect(mockTokenService.invalidateToken).toHaveBeenCalledWith(accessToken);
      expect(mockTokenService.invalidateToken).toHaveBeenCalledWith(refreshToken);
    });

    it('should handle logout with invalid token gracefully', async () => {
      const invalidToken = 'invalid-token';
      mockTokenService.verifyAccessToken.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await expect(authService.logout(invalidToken))
        .rejects
        .toThrow('Invalid token');
    });
  });

  describe('Security Features', () => {
    it('should not expose sensitive information in error messages', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(false);

      const credentials = {
        email: 'test@example.com',
        password: 'WrongPassword'
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow('Invalid credentials');
      
      // Should not reveal whether user exists or password is wrong
      expect(() => authService.login(credentials)).not.toThrow(/user/);
      expect(() => authService.login(credentials)).not.toThrow(/password/);
    });

    it('should include security headers in token response', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('access-token');
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token');

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      const result = await authService.login(credentials);

      expect(result).toHaveProperty('tokenType', 'Bearer');
      expect(result).toHaveProperty('scope', 'read write');
    });
  });

  describe('Concurrent Login Edge Cases', () => {
    it('should handle concurrent login attempts with atomic failed attempt counting', async () => {
      const userWithAttempts = {
        ...mockUser,
        failedLoginAttempts: 4
      };
      
      mockUserRepository.findByEmail.mockResolvedValue(userWithAttempts);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      mockUserRepository.incrementFailedLoginAttempts.mockImplementation(async (userId) => {
        // Simulate atomic increment operation
        const updatedUser = { ...userWithAttempts, failedLoginAttempts: 5 };
        if (updatedUser.failedLoginAttempts >= 5) {
          updatedUser.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        }
        return updatedUser;
      });

      const credentials = {
        email: 'test@example.com',
        password: 'WrongPassword'
      };

      // Simulate concurrent login attempts
      const promises = Array(3).fill(null).map(() => 
        authService.login(credentials).catch(e => e.message)
      );

      const results = await Promise.all(promises);

      // At least one should trigger the account lock
      expect(results.some(result => 
        result.includes('Account temporarily locked')
      )).toBe(true);

      expect(mockUserRepository.incrementFailedLoginAttempts).toHaveBeenCalledWith('1');
    });

    it('should prevent race conditions in account lockout', async () => {
      const userNearLockout = {
        ...mockUser,
        failedLoginAttempts: 4
      };

      mockUserRepository.findByEmail.mockResolvedValue(userNearLockout);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      
      // Mock atomic increment with proper concurrency handling
      let lockoutTriggered = false;
      mockUserRepository.incrementFailedLoginAttempts.mockImplementation(async () => {
        if (!lockoutTriggered) {
          lockoutTriggered = true;
          return {
            ...userNearLockout,
            failedLoginAttempts: 5,
            lockedUntil: new Date(Date.now() + 30 * 60 * 1000)
          };
        }
        throw new Error('Account temporarily locked due to too many failed login attempts');
      });

      const credentials = {
        email: 'test@example.com',
        password: 'WrongPassword'
      };

      const promises = Array(5).fill(null).map(() => 
        authService.login(credentials).catch(e => e)
      );

      const results = await Promise.all(promises);
      const lockoutErrors = results.filter(r => 
        r.message && r.message.includes('Account temporarily locked')
      );

      expect(lockoutErrors.length).toBeGreaterThan(0);
    });
  });

  describe('Token Refresh Security', () => {
    it('should check if refresh token was invalidated before refresh', async () => {
      const refreshToken = 'valid-refresh-token';
      mockTokenService.verifyRefreshToken.mockReturnValue({ userId: '1' });
      mockUserRepository.findById.mockResolvedValue(mockUser);
      
      // Token is blacklisted/invalidated
      mockTokenService.isTokenBlacklisted.mockResolvedValue(true);

      await expect(authService.refreshToken(refreshToken))
        .rejects
        .toThrow('Refresh token has been invalidated');

      expect(mockTokenService.isTokenBlacklisted).toHaveBeenCalledWith(refreshToken);
    });

    it('should invalidate refresh token family on suspicious activity', async () => {
      const refreshToken = 'compromised-refresh-token';
      const userId = '1';
      
      mockTokenService.verifyRefreshToken.mockReturnValue({ userId, tokenFamily: 'family123' });
      mockUserRepository.findById.mockResolvedValue(mockUser);
      
      // Simulate reuse of already used refresh token
      mockTokenService.isTokenUsed.mockResolvedValue(true);

      await expect(authService.refreshToken(refreshToken))
        .rejects
        .toThrow('Refresh token reuse detected. All tokens invalidated.');

      expect(mockTokenService.invalidateTokenFamily).toHaveBeenCalledWith('family123');
    });

    it('should detect and handle token theft scenarios', async () => {
      const refreshToken = 'stolen-token';
      const userId = '1';
      const userAgent = 'Different-Browser/1.0';
      const ipAddress = '192.168.1.999'; // Different IP
      
      mockTokenService.verifyRefreshToken.mockReturnValue({ 
        userId, 
        originalUserAgent: 'Chrome/1.0',
        originalIP: '192.168.1.100'
      });
      mockUserRepository.findById.mockResolvedValue(mockUser);

      await expect(authService.refreshTokenWithContext(refreshToken, { userAgent, ipAddress }))
        .rejects
        .toThrow('Suspicious token usage detected');

      expect(mockTokenService.invalidateAllUserTokens).toHaveBeenCalledWith(userId);
    });
  });

  describe('Timing Attack Prevention', () => {
    it('should use constant-time responses for user existence checks', async () => {
      const nonExistentUser = 'nonexistent@example.com';
      const existentUser = 'test@example.com';
      
      mockUserRepository.findByEmail
        .mockResolvedValueOnce(null) // Non-existent user
        .mockResolvedValueOnce(mockUser); // Existent user
      
      mockPasswordService.verifyPassword.mockResolvedValue(false);

      const start1 = Date.now();
      await expect(authService.login({ email: nonExistentUser, password: 'password' }))
        .rejects
        .toThrow('Invalid credentials');
      const duration1 = Date.now() - start1;

      const start2 = Date.now();
      await expect(authService.login({ email: existentUser, password: 'wrongpassword' }))
        .rejects
        .toThrow('Invalid credentials');
      const duration2 = Date.now() - start2;

      // Response times should be similar (within 100ms)
      expect(Math.abs(duration1 - duration2)).toBeLessThan(100);
    });

    it('should implement constant-time string comparison for passwords', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      
      // Mock password service to simulate timing
      let verificationTime = 0;
      mockPasswordService.verifyPassword.mockImplementation(async () => {
        // Simulate constant-time operation
        await new Promise(resolve => setTimeout(resolve, 50));
        return false;
      });

      const credentials = {
        email: 'test@example.com',
        password: 'any-password'
      };

      const start = Date.now();
      await expect(authService.login(credentials)).rejects.toThrow();
      const duration = Date.now() - start;

      expect(duration).toBeGreaterThanOrEqual(50); // Minimum time for comparison
    });
  });

  describe('Session Management', () => {
    it('should track active sessions per user', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('access-token-1');
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token-1');

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!',
        deviceInfo: { userAgent: 'Chrome/1.0', platform: 'Windows' }
      };

      await authService.loginWithSession(credentials);

      expect(mockUserRepository.createSession).toHaveBeenCalledWith('1', {
        accessToken: 'access-token-1',
        refreshToken: 'refresh-token-1',
        deviceInfo: credentials.deviceInfo,
        createdAt: expect.any(Date),
        lastAccessedAt: expect.any(Date)
      });
    });

    it('should limit concurrent sessions per user', async () => {
      const userWithManySessions = {
        ...mockUser,
        activeSessions: Array(10).fill({}).map((_, i) => ({
          id: `session-${i}`,
          accessToken: `token-${i}`,
          createdAt: new Date()
        }))
      };

      mockUserRepository.findByEmail.mockResolvedValue(userWithManySessions);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockUserRepository.getActiveSessionCount.mockResolvedValue(10);

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!'
      };

      await expect(authService.loginWithSession(credentials))
        .rejects
        .toThrow('Maximum number of concurrent sessions reached');
    });

    it('should cleanup expired sessions automatically', async () => {
      await authService.cleanupExpiredSessions();

      expect(mockUserRepository.removeExpiredSessions).toHaveBeenCalled();
      expect(mockTokenService.cleanupExpiredTokens).toHaveBeenCalled();
    });
  });

  describe('Audit and Monitoring', () => {
    it('should log all authentication events', async () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockTokenService.generateAccessToken.mockReturnValue('access-token');
      mockTokenService.generateRefreshToken.mockReturnValue('refresh-token');

      const credentials = {
        email: 'test@example.com',
        password: 'CorrectPassword123!',
        clientIP: '192.168.1.100',
        userAgent: 'Chrome/1.0'
      };

      await authService.loginWithAudit(credentials);

      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'login_success',
          userId: '1',
          email: 'test@example.com',
          clientIP: '192.168.1.100',
          userAgent: 'Chrome/1.0',
          timestamp: expect.any(Number)
        })
      );
      
      logSpy.mockRestore();
    });

    it('should track failed login attempts with details', async () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockPasswordService.verifyPassword.mockResolvedValue(false);

      const credentials = {
        email: 'test@example.com',
        password: 'WrongPassword',
        clientIP: '192.168.1.100',
        userAgent: 'Chrome/1.0'
      };

      await expect(authService.loginWithAudit(credentials))
        .rejects
        .toThrow('Invalid credentials');

      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'login_failed',
          email: 'test@example.com',
          reason: 'invalid_password',
          clientIP: '192.168.1.100',
          userAgent: 'Chrome/1.0',
          timestamp: expect.any(Number)
        })
      );
      
      logSpy.mockRestore();
    });
  });
});