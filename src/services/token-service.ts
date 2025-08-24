import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { TokenPayload } from '../types';

export class TokenService {
  private readonly jwtSecret: string;
  private readonly jwtExpiresIn = '1h';
  private readonly refreshTokenExpiresIn = '7d';
  private invalidatedTokens = new Set<string>();
  private blacklistedTokens = new Map<string, number>(); // token -> expiration timestamp
  private usedRefreshTokens = new Set<string>();
  private tokenFamilies = new Map<string, Set<string>>(); // family -> tokens

  constructor() {
    // Critical: Validate JWT secret in production
    if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET environment variable is required in production');
    }
    this.jwtSecret = process.env.JWT_SECRET || 'default-secret-for-testing';
    
    // Validate JWT secret strength
    if (this.jwtSecret.length < 32) {
      throw new Error('JWT secret must be at least 32 characters long');
    }
  }

  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.jwtExpiresIn,
    });
  }

  generateRefreshToken(userId: string, tokenFamily?: string): string {
    const family = tokenFamily || crypto.randomBytes(16).toString('hex');
    const payload = { userId, type: 'refresh', tokenFamily: family };
    const token = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.refreshTokenExpiresIn,
    });

    // Track token families for security
    if (!this.tokenFamilies.has(family)) {
      this.tokenFamilies.set(family, new Set());
    }
    this.tokenFamilies.get(family)!.add(token);

    return token;
  }

  generatePasswordResetToken(userId: string): string {
    const payload = { userId, type: 'password_reset' };
    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: '1h',
    });
  }

  verifyAccessToken(token: string): TokenPayload {
    if (this.invalidatedTokens.has(token)) {
      const error = new Error('Token has been invalidated');
      error.name = 'JsonWebTokenError';
      throw error;
    }

    return jwt.verify(token, this.jwtSecret) as TokenPayload;
  }

  verifyRefreshToken(token: string): { userId: string; tokenFamily?: string; originalUserAgent?: string; originalIP?: string } {
    if (this.invalidatedTokens.has(token)) {
      throw new Error('Invalid refresh token');
    }

    const decoded = jwt.verify(token, this.jwtSecret) as any;
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid refresh token');
    }

    return { 
      userId: decoded.userId, 
      tokenFamily: decoded.tokenFamily,
      originalUserAgent: decoded.originalUserAgent,
      originalIP: decoded.originalIP
    };
  }

  getTokenExpiration(): number {
    const expiresInSeconds = 3600; // 1 hour
    return Date.now() + (expiresInSeconds * 1000);
  }

  invalidateToken(token: string): void {
    this.invalidatedTokens.add(token);
  }

  async isTokenBlacklisted(token: string): Promise<boolean> {
    // Check if token is in blacklist and not expired
    const expiration = this.blacklistedTokens.get(token);
    if (!expiration) return false;
    
    if (Date.now() > expiration) {
      this.blacklistedTokens.delete(token);
      return false;
    }
    
    return true;
  }

  async isTokenUsed(token: string): Promise<boolean> {
    return this.usedRefreshTokens.has(token);
  }

  invalidateTokenFamily(tokenFamily: string): void {
    const tokens = this.tokenFamilies.get(tokenFamily);
    if (tokens) {
      tokens.forEach(token => {
        this.invalidatedTokens.add(token);
        this.blacklistedTokens.set(token, Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days
      });
      this.tokenFamilies.delete(tokenFamily);
    }
  }

  invalidateAllUserTokens(userId: string): void {
    // In a real implementation, this would query all user tokens from storage
    // For testing, we'll mark it as implemented with basic functionality
    
    // Invalidate all families that might belong to this user
    for (const [family, tokens] of this.tokenFamilies.entries()) {
      tokens.forEach(token => {
        try {
          const decoded = jwt.verify(token, this.jwtSecret) as any;
          if (decoded.userId === userId) {
            this.invalidateTokenFamily(family);
          }
        } catch (e) {
          // Token already expired or invalid, skip
        }
      });
    }
  }

  markTokenAsUsed(token: string): void {
    this.usedRefreshTokens.add(token);
  }

  cleanupExpiredTokens(): void {
    // Clean up expired blacklisted tokens
    const now = Date.now();
    for (const [token, expiration] of this.blacklistedTokens.entries()) {
      if (now > expiration) {
        this.blacklistedTokens.delete(token);
      }
    }

    // Clean up expired token families
    for (const [family, tokens] of this.tokenFamilies.entries()) {
      const validTokens = new Set<string>();
      tokens.forEach(token => {
        try {
          jwt.verify(token, this.jwtSecret);
          validTokens.add(token);
        } catch (e) {
          // Token expired, don't add to valid tokens
        }
      });
      
      if (validTokens.size === 0) {
        this.tokenFamilies.delete(family);
      } else {
        this.tokenFamilies.set(family, validTokens);
      }
    }
  }

  // Enhanced blacklist with expiration
  blacklistToken(token: string, expirationMs?: number): void {
    const expiration = expirationMs || (Date.now() + (24 * 60 * 60 * 1000)); // Default 24 hours
    this.blacklistedTokens.set(token, expiration);
    this.invalidatedTokens.add(token);
  }

  getBlacklistSize(): number {
    return this.blacklistedTokens.size;
  }

  clearExpiredFromMemory(): void {
    this.cleanupExpiredTokens();
  }
}