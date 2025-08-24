import { UserRepository } from '../repositories/user-repository';
import { PasswordService } from './password-service';
import { TokenService } from './token-service';
import { RateLimiter } from './rate-limiter';
import { LoginCredentials, LoginResponse, RefreshTokenResponse, TokenValidationResult } from '../types';

export class AuthService {
  private rateLimiter?: RateLimiter;
  private tokenService: TokenService;

  constructor(
    private userRepository: UserRepository,
    private passwordService: PasswordService,
    tokenServiceOrRateLimiter: TokenService | RateLimiter,
    rateLimiter?: RateLimiter
  ) {
    if (tokenServiceOrRateLimiter instanceof TokenService) {
      this.tokenService = tokenServiceOrRateLimiter;
      this.rateLimiter = rateLimiter;
    } else {
      // If third parameter is RateLimiter, we need a default TokenService
      this.tokenService = new TokenService();
      this.rateLimiter = tokenServiceOrRateLimiter as RateLimiter;
    }
  }

  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    // Basic validation
    if (!credentials.email) {
      throw new Error('Email is required');
    }

    if (!credentials.password) {
      throw new Error('Password is required');
    }

    // Normalize email to lowercase
    const normalizedEmail = credentials.email.toLowerCase();

    // Find user by email
    const user = await this.userRepository.findByEmail(normalizedEmail);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new Error('Account temporarily locked due to too many failed login attempts');
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verifyPassword(
      credentials.password,
      user.passwordHash
    );

    if (!isPasswordValid) {
      // Increment failed attempts
      await this.userRepository.incrementFailedLoginAttempts(user.id);
      throw new Error('Invalid credentials');
    }

    try {
      // Generate tokens
      const accessToken = this.tokenService.generateAccessToken({
        userId: user.id,
        email: user.email,
        username: user.username
      });

      const refreshToken = this.tokenService.generateRefreshToken(user.id);
      const expiresAt = this.tokenService.getTokenExpiration() || (Date.now() + (3600 * 1000));
      const expiresIn = 3600; // 1 hour in seconds

      // Update last login and reset failed attempts
      await this.userRepository.updateLastLogin(user.id);
      if (user.failedLoginAttempts && user.failedLoginAttempts > 0) {
        await this.userRepository.resetFailedLoginAttempts(user.id);
      }

      return {
        accessToken,
        refreshToken,
        expiresAt,
        expiresIn,
        tokenType: 'Bearer',
        scope: 'read write'
      };
    } catch (error) {
      throw new Error('Authentication failed');
    }
  }

  async loginWithRateLimit(credentials: LoginCredentials): Promise<LoginResponse> {
    if (!this.rateLimiter) {
      throw new Error('Rate limiter not configured');
    }

    // Check rate limits first
    if (credentials.clientIP) {
      const isAllowed = await this.rateLimiter.checkLoginAttempt(credentials.clientIP);
      if (!isAllowed) {
        throw new Error('Too many login attempts. Please try again later');
      }
    }

    const result = await this.login(credentials);

    // Track successful login for rate limiting adjustments
    if (credentials.clientIP) {
      await this.rateLimiter.cacheService.set(
        `successful_login:${credentials.clientIP}`,
        1,
        3600 // 1 hour
      );
    }

    return result;
  }

  async validateToken(token: string): Promise<TokenValidationResult> {
    if (!token) {
      return {
        valid: false,
        error: 'Token is required'
      };
    }

    try {
      const payload = this.tokenService.verifyAccessToken(token);
      return {
        valid: true,
        payload
      };
    } catch (error: any) {
      let errorMessage = 'Invalid token';
      
      if (error.name === 'TokenExpiredError') {
        errorMessage = 'Token expired';
      } else if (error.name === 'JsonWebTokenError') {
        errorMessage = 'Invalid token';
      }

      return {
        valid: false,
        error: errorMessage
      };
    }
  }

  async refreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await this.tokenService.isTokenBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new Error('Refresh token has been invalidated');
      }

      // Check if token was already used (potential theft)
      const isUsed = await this.tokenService.isTokenUsed(refreshToken);
      if (isUsed) {
        // Invalidate entire token family for security
        const decoded = this.tokenService.verifyRefreshToken(refreshToken);
        if (decoded.tokenFamily) {
          this.tokenService.invalidateTokenFamily(decoded.tokenFamily);
        }
        throw new Error('Refresh token reuse detected. All tokens invalidated.');
      }

      // Verify refresh token
      const decoded = this.tokenService.verifyRefreshToken(refreshToken);
      
      // Find user
      const user = await this.userRepository.findById(decoded.userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Mark the old token as used
      this.tokenService.markTokenAsUsed(refreshToken);

      // Generate new tokens
      const newAccessToken = this.tokenService.generateAccessToken({
        userId: user.id,
        email: user.email,
        username: user.username
      });

      const newRefreshToken = this.tokenService.generateRefreshToken(user.id, decoded.tokenFamily);
      const expiresAt = this.tokenService.getTokenExpiration() || (Date.now() + (3600 * 1000));
      const expiresIn = 3600; // 1 hour in seconds

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt,
        expiresIn
      };
    } catch (error: any) {
      if (error.message === 'User not found' || 
          error.message.includes('invalidated') || 
          error.message.includes('reuse detected')) {
        throw error;
      }
      throw new Error('Invalid refresh token');
    }
  }

  async logout(accessToken: string, refreshToken?: string): Promise<void> {
    // Verify the access token first
    const tokenValidation = await this.validateToken(accessToken);
    if (!tokenValidation.valid) {
      throw new Error('Invalid token');
    }

    // Invalidate tokens
    this.tokenService.invalidateToken(accessToken);
    if (refreshToken) {
      this.tokenService.invalidateToken(refreshToken);
    }
  }

  // Enhanced methods for security tests
  async refreshTokenWithContext(refreshToken: string, context: { userAgent: string; ipAddress: string }): Promise<RefreshTokenResponse> {
    const decoded = this.tokenService.verifyRefreshToken(refreshToken);
    
    // Detect suspicious token usage (different device/location)
    if (decoded.originalUserAgent && decoded.originalUserAgent !== context.userAgent) {
      this.tokenService.invalidateAllUserTokens(decoded.userId);
      throw new Error('Suspicious token usage detected');
    }
    
    if (decoded.originalIP && decoded.originalIP !== context.ipAddress) {
      this.tokenService.invalidateAllUserTokens(decoded.userId);
      throw new Error('Suspicious token usage detected');
    }

    return this.refreshToken(refreshToken);
  }

  async loginWithSession(credentials: LoginCredentials & { deviceInfo?: { userAgent: string; platform: string } }): Promise<LoginResponse> {
    const user = await this.userRepository.findByEmail(credentials.email.toLowerCase());
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Check session limits
    const activeSessionCount = await this.userRepository.getActiveSessionCount(user.id);
    if (activeSessionCount >= 10) {
      throw new Error('Maximum number of concurrent sessions reached');
    }

    const result = await this.login(credentials);

    // Create session tracking
    if (credentials.deviceInfo) {
      await this.userRepository.createSession(user.id, {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        deviceInfo: credentials.deviceInfo,
        createdAt: new Date(),
        lastAccessedAt: new Date()
      });
    }

    return result;
  }

  async cleanupExpiredSessions(): Promise<void> {
    await this.userRepository.removeExpiredSessions();
    this.tokenService.cleanupExpiredTokens();
  }

  async loginWithAudit(credentials: LoginCredentials & { clientIP?: string; userAgent?: string }): Promise<LoginResponse> {
    try {
      const result = await this.login(credentials);
      
      // Log successful login
      console.log({
        event: 'login_success',
        userId: result.accessToken ? 'extracted-from-token' : 'unknown', // In real app, extract from token
        email: credentials.email,
        clientIP: credentials.clientIP,
        userAgent: credentials.userAgent,
        timestamp: Date.now()
      });

      // Extract userId from token for proper logging
      const tokenValidation = await this.validateToken(result.accessToken);
      if (tokenValidation.valid && tokenValidation.payload) {
        console.log({
          event: 'login_success',
          userId: tokenValidation.payload.userId,
          email: credentials.email,
          clientIP: credentials.clientIP,
          userAgent: credentials.userAgent,
          timestamp: Date.now()
        });
      }

      return result;
    } catch (error) {
      // Log failed login
      console.log({
        event: 'login_failed',
        email: credentials.email,
        reason: 'invalid_password', // Simplified for demo
        clientIP: credentials.clientIP,
        userAgent: credentials.userAgent,
        timestamp: Date.now()
      });
      throw error;
    }
  }
}