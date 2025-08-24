# API Documentation

## User Authentication System API

This document describes the REST API endpoints for the user authentication system.

### Base URL
```
https://api.yourdomain.com/auth
```

### Authentication
Most endpoints require a valid JWT token in the Authorization header:
```
Authorization: Bearer <jwt-token>
```

---

## Authentication Endpoints

### POST /login
Authenticate user and return access tokens.

**Request Body:**
```typescript
{
  email: string;        // User's email address
  password: string;     // User's password
  clientIP?: string;    // Optional client IP for rate limiting
}
```

**Response (200 OK):**
```typescript
{
  accessToken: string;    // JWT access token
  refreshToken: string;   // JWT refresh token
  expiresAt: number;     // Token expiration timestamp
  expiresIn: number;     // Token TTL in seconds
  tokenType: "Bearer";   // Token type
  scope: string;         // Token scope/permissions
}
```

**Error Responses:**
- `400 Bad Request`: Missing email or password
- `401 Unauthorized`: Invalid credentials
- `423 Locked`: Account temporarily locked due to failed attempts
- `429 Too Many Requests`: Rate limit exceeded

**Example:**
```bash
curl -X POST /auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123"
  }'
```

---

### POST /refresh
Refresh an access token using a valid refresh token.

**Request Body:**
```typescript
{
  refreshToken: string;  // Valid refresh token
}
```

**Response (200 OK):**
```typescript
{
  accessToken: string;    // New JWT access token
  refreshToken: string;   // New refresh token (rotated)
  expiresAt: number;     // New token expiration timestamp
  expiresIn: number;     // New token TTL in seconds
  tokenType: "Bearer";   // Token type
  scope: string;         // Token scope/permissions
}
```

**Error Responses:**
- `400 Bad Request`: Missing or invalid refresh token
- `401 Unauthorized`: Refresh token expired or revoked

---

### POST /logout
Invalidate user tokens and end session.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

**Request Body:**
```typescript
{
  refreshToken?: string;  // Optional refresh token to invalidate
}
```

**Response (200 OK):**
```typescript
{
  message: "Successfully logged out"
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired token

---

## User Registration Endpoints

### POST /register
Register a new user account.

**Request Body:**
```typescript
{
  email: string;        // Valid email address (max 254 chars)
  username: string;     // Username (3-30 chars, alphanumeric + underscore)
  password: string;     // Password (min 8 chars, complexity requirements)
}
```

**Response (201 Created):**
```typescript
{
  id: string;          // Generated user ID
  email: string;       // User's email (normalized)
  username: string;    // User's username
  createdAt: Date;     // Account creation timestamp
}
```

**Error Responses:**
- `400 Bad Request`: Invalid input data or validation errors
- `409 Conflict`: Email or username already exists

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Cannot be a common password

**Example:**
```bash
curl -X POST /auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "username": "newuser123",
    "password": "SecurePass123!"
  }'
```

---

## Password Reset Endpoints

### POST /password-reset/request
Request a password reset for an email address.

**Request Body:**
```typescript
{
  email: string;  // Email address for password reset
}
```

**Response (200 OK):**
```typescript
{
  message: "If the email exists, a reset link has been sent"
}
```

**Notes:**
- Always returns 200 to prevent email enumeration
- Implements timing attack protection
- Rate limited per IP address

---

### POST /password-reset/verify
Verify a password reset token.

**Request Body:**
```typescript
{
  token: string;  // Password reset token from email
}
```

**Response (200 OK):**
```typescript
{
  valid: boolean;         // Whether token is valid
  email?: string;         // Email associated with token (if valid)
  expiresAt?: number;     // Token expiration timestamp
}
```

**Error Responses:**
- `400 Bad Request`: Missing token
- `401 Unauthorized`: Invalid or expired token

---

### POST /password-reset/confirm
Confirm password reset with new password.

**Request Body:**
```typescript
{
  token: string;           // Valid reset token
  newPassword: string;     // New password (same requirements as registration)
  confirmPassword: string; // Password confirmation (must match)
}
```

**Response (200 OK):**
```typescript
{
  success: boolean;
  message: "Password successfully reset"
}
```

**Error Responses:**
- `400 Bad Request`: Invalid token, passwords don't match, or weak password
- `401 Unauthorized`: Token expired or already used

---

## Token Validation Endpoints

### GET /validate
Validate a JWT token.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

**Response (200 OK):**
```typescript
{
  valid: boolean;          // Whether token is valid
  payload: {               // Token payload (if valid)
    userId: string;
    email: string;
    username: string;
    iat: number;          // Issued at timestamp
    exp: number;          // Expiration timestamp
  };
}
```

**Error Responses:**
- `400 Bad Request`: Missing token
- `401 Unauthorized`: Invalid, expired, or blacklisted token

---

## User Profile Endpoints

### GET /profile
Get current user profile information.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

**Response (200 OK):**
```typescript
{
  id: string;
  email: string;
  username: string;
  createdAt: Date;
  lastLoginAt?: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
}
```

---

## Rate Limiting

The API implements comprehensive rate limiting:

- **Login attempts**: 5 attempts per 15 minutes per IP
- **Registration**: 3 attempts per hour per IP  
- **Password reset**: 3 requests per hour per IP
- **Token refresh**: 10 requests per minute per user
- **General API**: 100 requests per minute per IP

**Rate Limit Headers:**
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1640995200
X-RateLimit-RetryAfter: 900
```

---

## Error Response Format

All error responses follow a consistent format:

```typescript
{
  error: {
    code: string;        // Error code (e.g., "INVALID_CREDENTIALS")
    message: string;     // Human-readable error message
    details?: any;       // Additional error details
    timestamp: string;   // ISO 8601 timestamp
    requestId: string;   // Unique request identifier
  }
}
```

**Common Error Codes:**
- `VALIDATION_ERROR`: Input validation failed
- `INVALID_CREDENTIALS`: Authentication failed
- `ACCOUNT_LOCKED`: Account temporarily locked
- `TOKEN_EXPIRED`: JWT token expired
- `TOKEN_INVALID`: JWT token invalid or malformed
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `EMAIL_NOT_FOUND`: Email address not found
- `USERNAME_TAKEN`: Username already exists
- `WEAK_PASSWORD`: Password doesn't meet security requirements

---

## Security Headers

All responses include security headers:

```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## API Versioning

The API uses URL versioning:
```
https://api.yourdomain.com/v1/auth/
```

Breaking changes will result in a new version. Non-breaking changes are released to the current version.

---

## Testing Endpoints

For development and testing environments only:

### POST /test/reset-rate-limit
Reset rate limiting for testing purposes.

### POST /test/generate-token
Generate test tokens with custom payloads.

**Note:** These endpoints are automatically disabled in production environments.

---

## SDKs and Libraries

Official SDKs available for:
- JavaScript/TypeScript
- Python
- Java
- .NET

Community SDKs:
- PHP
- Ruby
- Go

See the [SDK documentation](./SDKs.md) for implementation details.