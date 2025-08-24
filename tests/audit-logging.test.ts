import { AuditLogger } from '../src/services/audit-logger';
import { AuthService } from '../src/services/auth-service';
import { UserRegistrationService } from '../src/services/user-registration';
import { PasswordResetService } from '../src/services/password-reset-service';
import { RateLimiter } from '../src/services/rate-limiter';

jest.mock('../src/services/audit-logger');

describe('Audit Logging and Security Monitoring', () => {
  let auditLogger: jest.Mocked<AuditLogger>;
  let authService: AuthService;
  let originalConsoleLog: typeof console.log;
  let originalConsoleWarn: typeof console.warn;
  let originalConsoleError: typeof console.error;

  beforeEach(() => {
    auditLogger = new AuditLogger() as jest.Mocked<AuditLogger>;
    originalConsoleLog = console.log;
    originalConsoleWarn = console.warn;
    originalConsoleError = console.error;
    
    console.log = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.warn = originalConsoleWarn;
    console.error = originalConsoleError;
  });

  describe('Authentication Event Logging', () => {
    it('should log successful login events with complete context', async () => {
      const loginEvent = {
        event: 'login_success',
        userId: 'user123',
        email: 'test@example.com',
        clientIP: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        sessionId: 'session123',
        timestamp: Date.now(),
        geolocation: { country: 'US', city: 'New York' },
        deviceFingerprint: 'fp123'
      };

      auditLogger.logAuthenticationEvent(loginEvent);

      expect(auditLogger.logAuthenticationEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'login_success',
          userId: 'user123',
          email: 'test@example.com',
          clientIP: '192.168.1.100',
          userAgent: expect.any(String),
          timestamp: expect.any(Number)
        })
      );
    });

    it('should log failed login attempts with failure reasons', async () => {
      const failedLoginEvents = [
        {
          event: 'login_failed',
          email: 'test@example.com',
          reason: 'invalid_password',
          clientIP: '192.168.1.100',
          userAgent: 'Chrome/91.0',
          attemptNumber: 3,
          timestamp: Date.now()
        },
        {
          event: 'login_failed',
          email: 'nonexistent@example.com',
          reason: 'user_not_found',
          clientIP: '192.168.1.101',
          userAgent: 'Firefox/89.0',
          attemptNumber: 1,
          timestamp: Date.now()
        }
      ];

      failedLoginEvents.forEach(event => {
        auditLogger.logAuthenticationEvent(event);
      });

      expect(auditLogger.logAuthenticationEvent).toHaveBeenCalledTimes(2);
      expect(auditLogger.logAuthenticationEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'login_failed',
          reason: expect.stringMatching(/invalid_password|user_not_found/)
        })
      );
    });

    it('should log account lockout events', async () => {
      const lockoutEvent = {
        event: 'account_locked',
        userId: 'user123',
        email: 'test@example.com',
        reason: 'max_failed_attempts',
        failedAttempts: 5,
        lockoutDuration: 1800, // 30 minutes
        clientIP: '192.168.1.100',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(lockoutEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'account_locked',
          userId: 'user123',
          reason: 'max_failed_attempts',
          failedAttempts: 5
        })
      );
    });

    it('should log logout events', async () => {
      const logoutEvent = {
        event: 'logout',
        userId: 'user123',
        sessionId: 'session123',
        reason: 'user_initiated',
        sessionDuration: 3600,
        clientIP: '192.168.1.100',
        timestamp: Date.now()
      };

      auditLogger.logAuthenticationEvent(logoutEvent);

      expect(auditLogger.logAuthenticationEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'logout',
          userId: 'user123',
          reason: 'user_initiated',
          sessionDuration: 3600
        })
      );
    });
  });

  describe('Token Management Logging', () => {
    it('should log token generation events', async () => {
      const tokenEvent = {
        event: 'token_generated',
        userId: 'user123',
        tokenType: 'access_token',
        tokenId: 'token123',
        expiresAt: Date.now() + 3600000,
        scopes: ['read', 'write'],
        clientIP: '192.168.1.100',
        timestamp: Date.now()
      };

      auditLogger.logTokenEvent(tokenEvent);

      expect(auditLogger.logTokenEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'token_generated',
          tokenType: 'access_token',
          userId: 'user123'
        })
      );
    });

    it('should log token invalidation events', async () => {
      const invalidationEvent = {
        event: 'token_invalidated',
        tokenId: 'token123',
        tokenType: 'access_token',
        reason: 'user_logout',
        invalidatedBy: 'user123',
        remainingTTL: 1800,
        timestamp: Date.now()
      };

      auditLogger.logTokenEvent(invalidationEvent);

      expect(auditLogger.logTokenEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'token_invalidated',
          tokenId: 'token123',
          reason: 'user_logout'
        })
      );
    });

    it('should log suspicious token usage', async () => {
      const suspiciousEvent = {
        event: 'suspicious_token_usage',
        tokenId: 'token123',
        userId: 'user123',
        suspiciousActivity: 'different_ip',
        originalIP: '192.168.1.100',
        currentIP: '10.0.0.1',
        originalUserAgent: 'Chrome/91.0',
        currentUserAgent: 'Firefox/89.0',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(suspiciousEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'suspicious_token_usage',
          suspiciousActivity: 'different_ip',
          originalIP: '192.168.1.100',
          currentIP: '10.0.0.1'
        })
      );
    });
  });

  describe('Rate Limiting Event Logging', () => {
    it('should log rate limit violations', async () => {
      const rateLimitEvent = {
        event: 'rate_limit_exceeded',
        clientIP: '192.168.1.100',
        endpoint: '/auth/login',
        attempts: 10,
        timeWindow: 900, // 15 minutes
        blockDuration: 3600, // 1 hour
        userAgent: 'Chrome/91.0',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(rateLimitEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'rate_limit_exceeded',
          clientIP: '192.168.1.100',
          attempts: 10,
          endpoint: '/auth/login'
        })
      );
    });

    it('should log brute force attack detection', async () => {
      const bruteForceEvent = {
        event: 'brute_force_detected',
        clientIP: '192.168.1.100',
        targetEndpoint: '/auth/login',
        attemptCount: 50,
        timespan: 300, // 5 minutes
        attackPattern: 'rapid_succession',
        mitigation: 'ip_blocked',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(bruteForceEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'brute_force_detected',
          clientIP: '192.168.1.100',
          attemptCount: 50,
          attackPattern: 'rapid_succession'
        })
      );
    });
  });

  describe('User Management Event Logging', () => {
    it('should log user registration events', async () => {
      const registrationEvent = {
        event: 'user_registered',
        userId: 'newuser123',
        email: 'newuser@example.com',
        username: 'newuser',
        registrationMethod: 'direct',
        clientIP: '192.168.1.100',
        userAgent: 'Chrome/91.0',
        emailVerified: false,
        timestamp: Date.now()
      };

      auditLogger.logUserEvent(registrationEvent);

      expect(auditLogger.logUserEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'user_registered',
          userId: 'newuser123',
          email: 'newuser@example.com',
          registrationMethod: 'direct'
        })
      );
    });

    it('should log password change events', async () => {
      const passwordChangeEvent = {
        event: 'password_changed',
        userId: 'user123',
        changeMethod: 'user_initiated',
        requiresReauthentication: true,
        previousPasswordAge: 2592000, // 30 days
        clientIP: '192.168.1.100',
        timestamp: Date.now()
      };

      auditLogger.logUserEvent(passwordChangeEvent);

      expect(auditLogger.logUserEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'password_changed',
          userId: 'user123',
          changeMethod: 'user_initiated'
        })
      );
    });

    it('should log password reset events', async () => {
      const passwordResetEvents = [
        {
          event: 'password_reset_requested',
          email: 'user@example.com',
          resetToken: 'token123',
          requestIP: '192.168.1.100',
          timestamp: Date.now()
        },
        {
          event: 'password_reset_completed',
          userId: 'user123',
          resetToken: 'token123',
          clientIP: '192.168.1.100',
          timestamp: Date.now()
        }
      ];

      passwordResetEvents.forEach(event => {
        auditLogger.logUserEvent(event);
      });

      expect(auditLogger.logUserEvent).toHaveBeenCalledTimes(2);
    });
  });

  describe('Security Incident Logging', () => {
    it('should log malicious input detection', async () => {
      const maliciousInputEvent = {
        event: 'malicious_input_detected',
        inputType: 'XSS',
        payload: '<script>alert("xss")</script>',
        endpoint: '/auth/login',
        clientIP: '192.168.1.100',
        userAgent: 'Chrome/91.0',
        blocked: true,
        severity: 'high',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(maliciousInputEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'malicious_input_detected',
          inputType: 'XSS',
          severity: 'high',
          blocked: true
        })
      );
    });

    it('should log privilege escalation attempts', async () => {
      const escalationEvent = {
        event: 'privilege_escalation_attempt',
        userId: 'user123',
        attemptedAction: 'admin_access',
        currentRole: 'user',
        targetRole: 'admin',
        endpoint: '/admin/users',
        clientIP: '192.168.1.100',
        blocked: true,
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(escalationEvent);

      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'privilege_escalation_attempt',
          userId: 'user123',
          attemptedAction: 'admin_access',
          blocked: true
        })
      );
    });

    it('should log data access events', async () => {
      const dataAccessEvent = {
        event: 'sensitive_data_accessed',
        userId: 'user123',
        dataType: 'user_profiles',
        recordCount: 150,
        accessMethod: 'api',
        endpoint: '/api/users',
        queryParameters: { limit: 150, offset: 0 },
        clientIP: '192.168.1.100',
        timestamp: Date.now()
      };

      auditLogger.logDataEvent(dataAccessEvent);

      expect(auditLogger.logDataEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'sensitive_data_accessed',
          userId: 'user123',
          dataType: 'user_profiles',
          recordCount: 150
        })
      );
    });
  });

  describe('System Event Logging', () => {
    it('should log system startup and shutdown events', async () => {
      const systemEvents = [
        {
          event: 'system_startup',
          version: '1.0.0',
          environment: 'production',
          nodeVersion: process.version,
          timestamp: Date.now()
        },
        {
          event: 'system_shutdown',
          reason: 'maintenance',
          uptime: 86400000, // 24 hours
          activeConnections: 0,
          timestamp: Date.now()
        }
      ];

      systemEvents.forEach(event => {
        auditLogger.logSystemEvent(event);
      });

      expect(auditLogger.logSystemEvent).toHaveBeenCalledTimes(2);
    });

    it('should log configuration changes', async () => {
      const configChangeEvent = {
        event: 'configuration_changed',
        changedBy: 'admin123',
        configSection: 'rate_limiting',
        changes: {
          maxAttempts: { from: 5, to: 3 },
          windowMinutes: { from: 15, to: 10 }
        },
        timestamp: Date.now()
      };

      auditLogger.logSystemEvent(configChangeEvent);

      expect(auditLogger.logSystemEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'configuration_changed',
          changedBy: 'admin123',
          configSection: 'rate_limiting'
        })
      );
    });

    it('should log critical errors and exceptions', async () => {
      const errorEvent = {
        event: 'critical_error',
        errorType: 'DatabaseConnectionError',
        errorMessage: 'Connection to database failed',
        stackTrace: 'Error: Connection failed\n    at ...',
        affectedService: 'auth-service',
        clientIP: '192.168.1.100',
        userId: 'user123',
        timestamp: Date.now()
      };

      auditLogger.logSystemEvent(errorEvent);

      expect(auditLogger.logSystemEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'critical_error',
          errorType: 'DatabaseConnectionError',
          affectedService: 'auth-service'
        })
      );
    });
  });

  describe('Log Formatting and Structure', () => {
    it('should format logs in structured JSON format', () => {
      const event = {
        event: 'login_success',
        userId: 'user123',
        timestamp: Date.now()
      };

      auditLogger.logAuthenticationEvent(event);
      
      const logCall = auditLogger.logAuthenticationEvent.mock.calls[0][0];
      
      expect(logCall).toHaveProperty('event');
      expect(logCall).toHaveProperty('userId');
      expect(logCall).toHaveProperty('timestamp');
      expect(typeof logCall.timestamp).toBe('number');
    });

    it('should include correlation IDs for request tracking', () => {
      const eventWithCorrelation = {
        event: 'login_attempt',
        correlationId: 'req-123-456-789',
        traceId: 'trace-abc-def-ghi',
        userId: 'user123',
        timestamp: Date.now()
      };

      auditLogger.logAuthenticationEvent(eventWithCorrelation);

      expect(auditLogger.logAuthenticationEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          correlationId: 'req-123-456-789',
          traceId: 'trace-abc-def-ghi'
        })
      );
    });

    it('should sanitize sensitive data from logs', () => {
      const eventWithSensitiveData = {
        event: 'password_change_failed',
        userId: 'user123',
        password: 'super-secret-password',
        newPassword: 'new-secret-password',
        token: 'jwt-token-content',
        sessionId: 'session-secret',
        timestamp: Date.now()
      };

      auditLogger.logUserEvent(eventWithSensitiveData);

      const logCall = auditLogger.logUserEvent.mock.calls[0][0];
      
      expect(logCall).not.toHaveProperty('password');
      expect(logCall).not.toHaveProperty('newPassword');
      expect(logCall.token).toBe('[REDACTED]');
      expect(logCall.sessionId).toMatch(/^[a-zA-Z0-9]{8}\*{4}$/); // Partially redacted
    });
  });

  describe('Log Storage and Persistence', () => {
    it('should store logs in multiple destinations', async () => {
      const event = {
        event: 'critical_security_event',
        severity: 'critical',
        userId: 'user123',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(event);

      expect(auditLogger.writeToFile).toHaveBeenCalledWith(expect.any(String));
      expect(auditLogger.sendToSIEM).toHaveBeenCalledWith(event);
      expect(auditLogger.storeInDatabase).toHaveBeenCalledWith(event);
    });

    it('should handle log storage failures gracefully', async () => {
      auditLogger.writeToFile.mockRejectedValue(new Error('Disk full'));
      auditLogger.sendToSIEM.mockRejectedValue(new Error('SIEM unavailable'));

      const event = {
        event: 'test_event',
        timestamp: Date.now()
      };

      await expect(auditLogger.logSecurityEvent(event)).resolves.not.toThrow();
      
      expect(auditLogger.storeInDatabase).toHaveBeenCalled(); // Fallback should still work
    });

    it('should implement log rotation and archival', async () => {
      await auditLogger.rotateLogFiles();

      expect(auditLogger.archiveOldLogs).toHaveBeenCalled();
      expect(auditLogger.createNewLogFile).toHaveBeenCalled();
    });
  });

  describe('Real-time Alerting', () => {
    it('should trigger alerts for critical security events', async () => {
      const criticalEvent = {
        event: 'data_breach_attempt',
        severity: 'critical',
        userId: 'user123',
        dataAccessed: 'user_passwords',
        recordCount: 1000,
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(criticalEvent);

      expect(auditLogger.triggerAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          severity: 'critical',
          event: 'data_breach_attempt'
        })
      );
    });

    it('should aggregate similar events to prevent alert spam', async () => {
      const similarEvents = Array(10).fill(null).map((_, i) => ({
        event: 'login_failed',
        userId: 'user123',
        clientIP: '192.168.1.100',
        timestamp: Date.now() + i * 1000
      }));

      similarEvents.forEach(event => {
        auditLogger.logAuthenticationEvent(event);
      });

      expect(auditLogger.triggerAlert).toHaveBeenCalledTimes(1); // Should aggregate
      expect(auditLogger.triggerAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'repeated_login_failures',
          count: 10,
          aggregated: true
        })
      );
    });
  });

  describe('Compliance and Reporting', () => {
    it('should generate compliance reports for auditors', async () => {
      const reportRequest = {
        startDate: new Date('2023-01-01'),
        endDate: new Date('2023-12-31'),
        eventTypes: ['login_success', 'login_failed', 'password_changed'],
        userId: 'user123'
      };

      const report = await auditLogger.generateComplianceReport(reportRequest);

      expect(report).toHaveProperty('events');
      expect(report).toHaveProperty('summary');
      expect(report.events).toBeInstanceOf(Array);
      expect(report.summary).toHaveProperty('totalEvents');
      expect(report.summary).toHaveProperty('eventsByType');
    });

    it('should export logs in standard formats (SIEM, CSV, JSON)', async () => {
      const exportRequest = {
        format: 'SIEM',
        startDate: new Date('2023-01-01'),
        endDate: new Date('2023-12-31')
      };

      const exportResult = await auditLogger.exportLogs(exportRequest);

      expect(exportResult).toHaveProperty('format', 'SIEM');
      expect(exportResult).toHaveProperty('data');
      expect(exportResult).toHaveProperty('recordCount');
    });

    it('should maintain log integrity with checksums', async () => {
      const event = {
        event: 'integrity_test',
        userId: 'user123',
        timestamp: Date.now()
      };

      auditLogger.logSecurityEvent(event);

      expect(auditLogger.calculateChecksum).toHaveBeenCalledWith(expect.any(String));
      expect(auditLogger.storeChecksum).toHaveBeenCalledWith(expect.any(String));
    });
  });
});