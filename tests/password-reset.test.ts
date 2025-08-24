import { PasswordResetService } from '../src/services/password-reset-service';
import { UserRepository } from '../src/repositories/user-repository';
import { EmailService } from '../src/services/email-service';
import { PasswordService } from '../src/services/password-service';
import { TokenService } from '../src/services/token-service';
import crypto from 'crypto';

jest.mock('../src/repositories/user-repository');
jest.mock('../src/services/email-service');
jest.mock('../src/services/password-service');
jest.mock('../src/services/token-service');
jest.mock('crypto');

describe('Password Reset Service', () => {
  let passwordResetService: PasswordResetService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;
  let mockPasswordService: jest.Mocked<PasswordService>;
  let mockTokenService: jest.Mocked<TokenService>;
  let mockCrypto: jest.Mocked<typeof crypto>;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    username: 'testuser',
    passwordHash: '$2b$12$hashedPassword',
    createdAt: new Date(),
    updatedAt: new Date()
  };

  beforeEach(() => {
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockEmailService = new EmailService() as jest.Mocked<EmailService>;
    mockPasswordService = new PasswordService() as jest.Mocked<PasswordService>;
    mockTokenService = new TokenService() as jest.Mocked<TokenService>;
    mockCrypto = crypto as jest.Mocked<typeof crypto>;

    passwordResetService = new PasswordResetService(
      mockUserRepository,
      mockEmailService,
      mockPasswordService,
      mockTokenService
    );
  });

  describe('Request Password Reset', () => {
    it('should reject empty email', async () => {
      await expect(passwordResetService.requestPasswordReset(''))
        .rejects
        .toThrow('Email is required');
    });

    it('should reject invalid email format', async () => {
      await expect(passwordResetService.requestPasswordReset('invalid-email'))
        .rejects
        .toThrow('Invalid email format');
    });

    it('should handle non-existent user gracefully with constant timing', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(null);
      
      // Simulate database lookup time even for non-existent users
      mockPasswordService.hashPassword.mockImplementation(() => 
        new Promise(resolve => setTimeout(() => resolve('dummy-hash'), 100))
      );

      const start = Date.now();
      const result = await passwordResetService.requestPasswordReset('nonexistent@example.com');
      const duration = Date.now() - start;

      expect(result).toEqual({
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      });
      
      expect(mockEmailService.sendPasswordResetEmail).not.toHaveBeenCalled();
      expect(duration).toBeGreaterThanOrEqual(90); // Should take similar time as real user
    });

    it('should generate secure reset token for valid user', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockCrypto.randomBytes.mockReturnValue(Buffer.from('securetoken123'));
      mockTokenService.generatePasswordResetToken.mockReturnValue('secure-reset-token');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(true);

      const result = await passwordResetService.requestPasswordReset('test@example.com');

      expect(result.success).toBe(true);
      expect(mockTokenService.generatePasswordResetToken).toHaveBeenCalledWith('1');
      expect(mockUserRepository.storePasswordResetToken).toHaveBeenCalledWith(
        '1',
        'secure-reset-token',
        expect.any(Date)
      );
    });

    it('should send password reset email with valid token', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePasswordResetToken.mockReturnValue('reset-token-123');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(true);

      await passwordResetService.requestPasswordReset('test@example.com');

      expect(mockEmailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        'test@example.com',
        'testuser',
        'reset-token-123'
      );
    });

    it('should set token expiration time', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePasswordResetToken.mockReturnValue('reset-token-123');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(true);

      await passwordResetService.requestPasswordReset('test@example.com');

      expect(mockUserRepository.storePasswordResetToken).toHaveBeenCalledWith(
        '1',
        'reset-token-123',
        expect.any(Date)
      );

      const expirationCall = mockUserRepository.storePasswordResetToken.mock.calls[0];
      const expirationTime = expirationCall[2] as Date;
      const now = new Date();
      const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);
      
      expect(expirationTime.getTime()).toBeGreaterThan(now.getTime());
      expect(expirationTime.getTime()).toBeLessThanOrEqual(oneHourFromNow.getTime());
    });

    it('should handle email service failures', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePasswordResetToken.mockReturnValue('reset-token-123');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(false);

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Failed to send password reset email');
    });

    it('should prevent multiple concurrent reset requests', async () => {
      const userWithPendingReset = {
        ...mockUser,
        passwordResetToken: 'existing-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes from now
      };
      
      mockUserRepository.findByEmail.mockResolvedValue(userWithPendingReset);

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Password reset already requested. Please check your email or wait before requesting again');
    });
  });

  describe('Validate Reset Token', () => {
    it('should reject empty token', async () => {
      await expect(passwordResetService.validateResetToken(''))
        .rejects
        .toThrow('Reset token is required');
    });

    it('should reject invalid token format', async () => {
      await expect(passwordResetService.validateResetToken('invalid-token'))
        .rejects
        .toThrow('Invalid token format');
    });

    it('should reject non-existent token', async () => {
      mockUserRepository.findByPasswordResetToken.mockResolvedValue(null);

      await expect(passwordResetService.validateResetToken('valid-format-token'))
        .rejects
        .toThrow('Invalid or expired reset token');
    });

    it('should reject expired token', async () => {
      const userWithExpiredToken = {
        ...mockUser,
        passwordResetToken: 'valid-token',
        passwordResetExpires: new Date(Date.now() - 60 * 60 * 1000) // 1 hour ago
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithExpiredToken);

      await expect(passwordResetService.validateResetToken('valid-token'))
        .rejects
        .toThrow('Invalid or expired reset token');
    });

    it('should accept valid non-expired token', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes from now
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);

      const result = await passwordResetService.validateResetToken('valid-token');

      expect(result).toEqual({
        valid: true,
        userId: '1',
        email: 'test@example.com'
      });
    });
  });

  describe('Reset Password', () => {
    const validResetData = {
      token: 'valid-reset-token',
      newPassword: 'NewSecurePassword123!',
      confirmPassword: 'NewSecurePassword123!'
    };

    it('should reject empty token', async () => {
      const invalidData = { ...validResetData, token: '' };

      await expect(passwordResetService.resetPassword(invalidData))
        .rejects
        .toThrow('Reset token is required');
    });

    it('should reject empty new password', async () => {
      const invalidData = { ...validResetData, newPassword: '' };

      await expect(passwordResetService.resetPassword(invalidData))
        .rejects
        .toThrow('New password is required');
    });

    it('should reject password confirmation mismatch', async () => {
      const invalidData = {
        ...validResetData,
        confirmPassword: 'DifferentPassword123!'
      };

      await expect(passwordResetService.resetPassword(invalidData))
        .rejects
        .toThrow('Password confirmation does not match');
    });

    it('should validate new password strength', async () => {
      const weakPasswordData = {
        ...validResetData,
        newPassword: 'weak',
        confirmPassword: 'weak'
      };

      await expect(passwordResetService.resetPassword(weakPasswordData))
        .rejects
        .toThrow('Password must be at least 8 characters long');
    });

    it('should prevent reusing current password', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(true); // Same as current password

      await expect(passwordResetService.resetPassword(validResetData))
        .rejects
        .toThrow('New password cannot be the same as current password');
    });

    it('should successfully reset password with valid data', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(false); // Different from current password
      mockPasswordService.hashPassword.mockResolvedValue('new-hashed-password');
      mockEmailService.sendPasswordChangeNotification.mockResolvedValue(true);

      const result = await passwordResetService.resetPassword(validResetData);

      expect(result.success).toBe(true);
      expect(mockPasswordService.hashPassword).toHaveBeenCalledWith('NewSecurePassword123!');
      expect(mockUserRepository.updatePassword).toHaveBeenCalledWith('1', 'new-hashed-password');
      expect(mockUserRepository.clearPasswordResetToken).toHaveBeenCalledWith('1');
    });

    it('should send password change notification email', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      mockPasswordService.hashPassword.mockResolvedValue('new-hashed-password');
      mockEmailService.sendPasswordChangeNotification.mockResolvedValue(true);

      await passwordResetService.resetPassword(validResetData);

      expect(mockEmailService.sendPasswordChangeNotification).toHaveBeenCalledWith(
        'test@example.com',
        'testuser'
      );
    });

    it('should invalidate all user sessions after password reset', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      mockPasswordService.hashPassword.mockResolvedValue('new-hashed-password');
      mockEmailService.sendPasswordChangeNotification.mockResolvedValue(true);

      await passwordResetService.resetPassword(validResetData);

      expect(mockTokenService.invalidateAllUserTokens).toHaveBeenCalledWith('1');
    });
  });

  describe('Security Features', () => {
    it('should use cryptographically secure token generation', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockCrypto.randomBytes.mockReturnValue(Buffer.from('cryptographically-secure-bytes'));
      mockTokenService.generatePasswordResetToken.mockReturnValue('secure-token');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(true);

      await passwordResetService.requestPasswordReset('test@example.com');

      expect(mockCrypto.randomBytes).toHaveBeenCalledWith(32);
    });

    it('should rate limit password reset requests per email', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockUserRepository.getPasswordResetAttempts.mockResolvedValue(5); // Too many attempts

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Too many password reset requests. Please try again later');
    });

    it('should rate limit password reset requests per IP', async () => {
      const ipAddress = '192.168.1.1';
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockUserRepository.getPasswordResetAttemptsByIP.mockResolvedValue(10); // Too many attempts

      await expect(passwordResetService.requestPasswordReset('test@example.com', ipAddress))
        .rejects
        .toThrow('Too many password reset requests from this IP. Please try again later');
    });

    it('should log password reset activities', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      mockPasswordService.hashPassword.mockResolvedValue('new-hashed-password');
      mockEmailService.sendPasswordChangeNotification.mockResolvedValue(true);

      await passwordResetService.resetPassword(validResetData);

      expect(mockUserRepository.logPasswordResetActivity).toHaveBeenCalledWith(
        '1',
        'password_reset_completed',
        expect.any(Object)
      );
    });

    it('should clear reset token after successful use', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      mockPasswordService.hashPassword.mockResolvedValue('new-hashed-password');
      mockEmailService.sendPasswordChangeNotification.mockResolvedValue(true);

      await passwordResetService.resetPassword(validResetData);

      expect(mockUserRepository.clearPasswordResetToken).toHaveBeenCalledWith('1');
    });

    it('should clear reset token after failed attempts threshold', async () => {
      const userWithValidToken = {
        ...mockUser,
        passwordResetToken: 'valid-reset-token',
        passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000),
        passwordResetAttempts: 5 // Max attempts reached
      };

      mockUserRepository.findByPasswordResetToken.mockResolvedValue(userWithValidToken);

      await expect(passwordResetService.validateResetToken('valid-reset-token'))
        .rejects
        .toThrow('Reset token has been invalidated due to too many failed attempts');

      expect(mockUserRepository.clearPasswordResetToken).toHaveBeenCalledWith('1');
    });
  });

  describe('Edge Cases', () => {
    it('should handle database connection failures gracefully', async () => {
      mockUserRepository.findByEmail.mockRejectedValue(new Error('Database connection failed'));

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Service temporarily unavailable');
    });

    it('should handle email service outages', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePasswordResetToken.mockReturnValue('reset-token');
      mockEmailService.sendPasswordResetEmail.mockRejectedValue(new Error('SMTP server down'));

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Unable to send password reset email. Please try again later');
    });

    it('should handle token generation failures', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      mockTokenService.generatePasswordResetToken.mockImplementation(() => {
        throw new Error('Token generation failed');
      });

      await expect(passwordResetService.requestPasswordReset('test@example.com'))
        .rejects
        .toThrow('Failed to generate reset token');
    });

    it('should cleanup expired tokens periodically', async () => {
      await passwordResetService.cleanupExpiredTokens();

      expect(mockUserRepository.removeExpiredPasswordResetTokens).toHaveBeenCalled();
    });
  });
});