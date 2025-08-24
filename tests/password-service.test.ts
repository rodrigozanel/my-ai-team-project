import bcrypt from 'bcrypt';
import { PasswordService } from '../src/services/password-service';

jest.mock('bcrypt');

describe('Password Service', () => {
  let passwordService: PasswordService;
  const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

  beforeEach(() => {
    passwordService = new PasswordService();
    jest.clearAllMocks();
  });

  describe('Password Hashing', () => {
    it('should hash password with default salt rounds', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);

      const result = await passwordService.hashPassword(plainPassword);

      expect(result).toBe(hashedPassword);
      expect(mockBcrypt.hash).toHaveBeenCalledWith(plainPassword, 12);
    });

    it('should hash password with custom salt rounds', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$10$hashedPasswordExample';
      const customSaltRounds = 10;
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);

      const result = await passwordService.hashPassword(plainPassword, customSaltRounds);

      expect(result).toBe(hashedPassword);
      expect(mockBcrypt.hash).toHaveBeenCalledWith(plainPassword, customSaltRounds);
    });

    it('should handle bcrypt errors gracefully', async () => {
      const plainPassword = 'TestPassword123!';
      const error = new Error('Bcrypt hashing failed');
      
      mockBcrypt.hash.mockRejectedValue(error);

      await expect(passwordService.hashPassword(plainPassword))
        .rejects
        .toThrow('Password hashing failed');
    });

    it('should reject empty password for hashing', async () => {
      await expect(passwordService.hashPassword(''))
        .rejects
        .toThrow('Password cannot be empty');
    });

    it('should reject null/undefined password for hashing', async () => {
      await expect(passwordService.hashPassword(null as any))
        .rejects
        .toThrow('Password cannot be empty');

      await expect(passwordService.hashPassword(undefined as any))
        .rejects
        .toThrow('Password cannot be empty');
    });

    it('should handle extremely long passwords', async () => {
      const longPassword = 'a'.repeat(1000);
      const hashedPassword = '$2b$12$hashedLongPasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);

      const result = await passwordService.hashPassword(longPassword);

      expect(result).toBe(hashedPassword);
      expect(mockBcrypt.hash).toHaveBeenCalledWith(longPassword, 12);
    });
  });

  describe('Password Verification', () => {
    it('should verify correct password', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.compare.mockResolvedValue(true as never);

      const result = await passwordService.verifyPassword(plainPassword, hashedPassword);

      expect(result).toBe(true);
      expect(mockBcrypt.compare).toHaveBeenCalledWith(plainPassword, hashedPassword);
    });

    it('should reject incorrect password', async () => {
      const plainPassword = 'WrongPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.compare.mockResolvedValue(false as never);

      const result = await passwordService.verifyPassword(plainPassword, hashedPassword);

      expect(result).toBe(false);
      expect(mockBcrypt.compare).toHaveBeenCalledWith(plainPassword, hashedPassword);
    });

    it('should handle bcrypt comparison errors', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      const error = new Error('Bcrypt comparison failed');
      
      mockBcrypt.compare.mockRejectedValue(error);

      await expect(passwordService.verifyPassword(plainPassword, hashedPassword))
        .rejects
        .toThrow('Password verification failed');
    });

    it('should reject empty plain password for verification', async () => {
      const hashedPassword = '$2b$12$hashedPasswordExample';

      await expect(passwordService.verifyPassword('', hashedPassword))
        .rejects
        .toThrow('Plain password cannot be empty');
    });

    it('should reject empty hashed password for verification', async () => {
      const plainPassword = 'TestPassword123!';

      await expect(passwordService.verifyPassword(plainPassword, ''))
        .rejects
        .toThrow('Hashed password cannot be empty');
    });

    it('should reject null/undefined passwords for verification', async () => {
      const hashedPassword = '$2b$12$hashedPasswordExample';
      const plainPassword = 'TestPassword123!';

      await expect(passwordService.verifyPassword(null as any, hashedPassword))
        .rejects
        .toThrow('Plain password cannot be empty');

      await expect(passwordService.verifyPassword(plainPassword, null as any))
        .rejects
        .toThrow('Hashed password cannot be empty');
    });

    it('should handle malformed hash gracefully', async () => {
      const plainPassword = 'TestPassword123!';
      const malformedHash = 'not-a-valid-hash';
      
      mockBcrypt.compare.mockResolvedValue(false as never);

      const result = await passwordService.verifyPassword(plainPassword, malformedHash);

      expect(result).toBe(false);
      expect(mockBcrypt.compare).toHaveBeenCalledWith(plainPassword, malformedHash);
    });
  });

  describe('Security Properties', () => {
    it('should produce different hashes for same password', async () => {
      const plainPassword = 'TestPassword123!';
      const hash1 = '$2b$12$salt1hashedPasswordExample';
      const hash2 = '$2b$12$salt2hashedPasswordExample';
      
      mockBcrypt.hash
        .mockResolvedValueOnce(hash1 as never)
        .mockResolvedValueOnce(hash2 as never);

      const result1 = await passwordService.hashPassword(plainPassword);
      const result2 = await passwordService.hashPassword(plainPassword);

      expect(result1).not.toBe(result2);
      expect(mockBcrypt.hash).toHaveBeenCalledTimes(2);
    });

    it('should use secure salt rounds by default', async () => {
      const plainPassword = 'TestPassword123!';
      
      mockBcrypt.hash.mockResolvedValue('$2b$12$hashedPasswordExample' as never);

      await passwordService.hashPassword(plainPassword);

      expect(mockBcrypt.hash).toHaveBeenCalledWith(plainPassword, 12);
    });

    it('should verify password regardless of case changes in plain text', async () => {
      const plainPassword = 'TestPassword123!';
      const differentCasePassword = 'testpassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.compare.mockResolvedValue(false as never);

      const result = await passwordService.verifyPassword(differentCasePassword, hashedPassword);

      expect(result).toBe(false);
      expect(mockBcrypt.compare).toHaveBeenCalledWith(differentCasePassword, hashedPassword);
    });
  });

  describe('Performance and Resource Management', () => {
    it('should complete password hashing within reasonable time', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);

      const startTime = Date.now();
      await passwordService.hashPassword(plainPassword);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(5000);
    });

    it('should complete password verification within reasonable time', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.compare.mockResolvedValue(true as never);

      const startTime = Date.now();
      await passwordService.verifyPassword(plainPassword, hashedPassword);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(5000);
    });

    it('should handle concurrent password operations', async () => {
      const plainPassword = 'TestPassword123!';
      const hashedPassword = '$2b$12$hashedPasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);
      mockBcrypt.compare.mockResolvedValue(true as never);

      const hashPromises = Array(5).fill(null).map(() => 
        passwordService.hashPassword(plainPassword)
      );
      
      const verifyPromises = Array(5).fill(null).map(() => 
        passwordService.verifyPassword(plainPassword, hashedPassword)
      );

      const [hashResults, verifyResults] = await Promise.all([
        Promise.all(hashPromises),
        Promise.all(verifyPromises)
      ]);

      expect(hashResults).toHaveLength(5);
      expect(verifyResults).toHaveLength(5);
      expect(verifyResults.every(result => result === true)).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle password with special characters', async () => {
      const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const hashedPassword = '$2b$12$hashedSpecialPasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);
      mockBcrypt.compare.mockResolvedValue(true as never);

      const hash = await passwordService.hashPassword(specialPassword);
      const isValid = await passwordService.verifyPassword(specialPassword, hash);

      expect(hash).toBe(hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should handle password with unicode characters', async () => {
      const unicodePassword = 'pássw🔐rd123!';
      const hashedPassword = '$2b$12$hashedUnicodePasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);
      mockBcrypt.compare.mockResolvedValue(true as never);

      const hash = await passwordService.hashPassword(unicodePassword);
      const isValid = await passwordService.verifyPassword(unicodePassword, hash);

      expect(hash).toBe(hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should handle whitespace in passwords correctly', async () => {
      const passwordWithSpaces = '  Test Password 123!  ';
      const hashedPassword = '$2b$12$hashedSpacePasswordExample';
      
      mockBcrypt.hash.mockResolvedValue(hashedPassword as never);
      mockBcrypt.compare.mockResolvedValue(true as never);

      const hash = await passwordService.hashPassword(passwordWithSpaces);
      const isValid = await passwordService.verifyPassword(passwordWithSpaces, hash);

      expect(hash).toBe(hashedPassword);
      expect(isValid).toBe(true);
      expect(mockBcrypt.hash).toHaveBeenCalledWith(passwordWithSpaces, 12);
    });
  });
});