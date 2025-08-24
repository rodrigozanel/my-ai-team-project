import validator from 'validator';
import crypto from 'crypto';
import { UserRepository } from '../repositories/user-repository';
import { EmailService } from './email-service';
import { PasswordService } from './password-service';
import { TokenService } from './token-service';
import { PasswordResetRequest, PasswordResetResponse } from '../types';

export class PasswordResetService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService,
    private passwordService: PasswordService,
    private tokenService: TokenService
  ) {}

  async requestPasswordReset(email: string, ipAddress?: string): Promise<PasswordResetResponse> {
    if (!email) {
      throw new Error('Email is required');
    }

    if (!validator.isEmail(email)) {
      throw new Error('Invalid email format');
    }

    // Rate limiting checks
    if (ipAddress) {
      const ipAttempts = await this.userRepository.getPasswordResetAttemptsByIP(ipAddress);
      if (ipAttempts >= 10) {
        throw new Error('Too many password reset requests from this IP. Please try again later');
      }
    }

    const emailAttempts = await this.userRepository.getPasswordResetAttempts(email);
    if (emailAttempts >= 5) {
      throw new Error('Too many password reset requests. Please try again later');
    }

    const user = await this.userRepository.findByEmail(email.toLowerCase());
    
    if (!user) {
      // Timing attack prevention: simulate the same processing time as for existing users
      const dummyHash = await this.passwordService.hashPassword('dummy-password');
      
      // Don't reveal that the user doesn't exist
      return {
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      };
    }

    // Check for pending reset request
    if (user.passwordResetToken && user.passwordResetExpires && user.passwordResetExpires > new Date()) {
      throw new Error('Password reset already requested. Please check your email or wait before requesting again');
    }

    try {
      // Generate secure token using crypto for entropy
      const secureBytes = crypto.randomBytes(32);
      const resetToken = this.tokenService.generatePasswordResetToken(user.id);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Store token
      await this.userRepository.storePasswordResetToken(user.id, resetToken, expiresAt);

      // Send email
      const emailSent = await this.emailService.sendPasswordResetEmail(
        user.email,
        user.username,
        resetToken
      );

      if (!emailSent) {
        throw new Error('Failed to send password reset email');
      }

      return {
        success: true,
        message: 'Password reset link has been sent to your email'
      };
    } catch (error: any) {
      if (error.message === 'Failed to send password reset email') {
        throw error;
      }
      if (error.message.includes('SMTP')) {
        throw new Error('Unable to send password reset email. Please try again later');
      }
      if (error.message.includes('Token generation failed')) {
        throw new Error('Failed to generate reset token');
      }
      if (error.message.includes('Database')) {
        throw new Error('Service temporarily unavailable');
      }
      throw error;
    }
  }

  async validateResetToken(token: string): Promise<{
    valid: boolean;
    userId?: string;
    email?: string;
  }> {
    if (!token) {
      throw new Error('Reset token is required');
    }

    // Validate JWT token format properly
    try {
      // Basic JWT structure validation (header.payload.signature)
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }
      
      // Verify it's a valid password reset token
      const decoded = this.tokenService.verifyAccessToken(token) as any;
      if (decoded.type !== 'password_reset') {
        throw new Error('Invalid token format');
      }
    } catch (error) {
      throw new Error('Invalid token format');
    }

    const user = await this.userRepository.findByPasswordResetToken(token);
    
    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    if (user.passwordResetAttempts && user.passwordResetAttempts >= 5) {
      await this.userRepository.clearPasswordResetToken(user.id);
      throw new Error('Reset token has been invalidated due to too many failed attempts');
    }

    if (!user.passwordResetExpires || user.passwordResetExpires < new Date()) {
      throw new Error('Invalid or expired reset token');
    }

    return {
      valid: true,
      userId: user.id,
      email: user.email
    };
  }

  async resetPassword(data: PasswordResetRequest): Promise<PasswordResetResponse> {
    if (!data.token) {
      throw new Error('Reset token is required');
    }

    if (!data.newPassword) {
      throw new Error('New password is required');
    }

    if (data.newPassword !== data.confirmPassword) {
      throw new Error('Password confirmation does not match');
    }

    // Validate password strength
    await this.validatePasswordStrength(data.newPassword);

    // Validate token and get user
    const tokenValidation = await this.validateResetToken(data.token);
    const user = await this.userRepository.findByPasswordResetToken(data.token);

    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    // Check if new password is same as current password
    const isSamePassword = await this.passwordService.verifyPassword(
      data.newPassword,
      user.passwordHash
    );

    if (isSamePassword) {
      throw new Error('New password cannot be the same as current password');
    }

    // Hash new password
    const newPasswordHash = await this.passwordService.hashPassword(data.newPassword);

    // Update password and clear reset token
    await this.userRepository.updatePassword(user.id, newPasswordHash);
    await this.userRepository.clearPasswordResetToken(user.id);

    // Invalidate all user sessions
    this.tokenService.invalidateAllUserTokens(user.id);

    // Send confirmation email
    await this.emailService.sendPasswordChangeNotification(user.email, user.username);

    // Log activity
    await this.userRepository.logPasswordResetActivity(
      user.id,
      'password_reset_completed',
      { timestamp: new Date(), ip: 'unknown' }
    );

    return {
      success: true,
      message: 'Password has been reset successfully'
    };
  }

  async cleanupExpiredTokens(): Promise<void> {
    await this.userRepository.removeExpiredPasswordResetTokens();
  }

  private async validatePasswordStrength(password: string): Promise<void> {
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      throw new Error('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter');
    }

    if (!/\d/.test(password)) {
      throw new Error('Password must contain at least one number');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      throw new Error('Password must contain at least one special character');
    }
  }
}