export interface User {
  id: string;
  email: string;
  username: string;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date | null;
  failedLoginAttempts?: number;
  lockedUntil?: Date | null;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  passwordResetAttempts?: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
  clientIP?: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  expiresIn: number;
  tokenType: string;
  scope: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  expiresIn: number;
}

export interface TokenPayload {
  userId: string;
  email: string;
  username: string;
  iat?: number;
  exp?: number;
}

export interface TokenValidationResult {
  valid: boolean;
  payload?: TokenPayload;
  error?: string;
}

export interface RegistrationData {
  email: string;
  username: string;
  password: string;
}

export interface RegistrationResponse {
  id: string;
  email: string;
  username: string;
  createdAt: Date;
}

export interface PasswordResetRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordResetResponse {
  success: boolean;
  message?: string;
}

export interface RateLimitConfiguration {
  maxAttempts: number;
  windowMinutes: number;
  lockoutMinutes: number;
}