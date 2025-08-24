import validator from 'validator';
import { UserRegistrationService } from '../src/services/user-registration';
import { UserRepository } from '../src/repositories/user-repository';
import { PasswordService } from '../src/services/password-service';

jest.mock('../src/repositories/user-repository');
jest.mock('../src/services/password-service');
jest.mock('validator');

describe('User Registration', () => {
  let registrationService: UserRegistrationService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockPasswordService: jest.Mocked<PasswordService>;

  beforeEach(() => {
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockPasswordService = new PasswordService() as jest.Mocked<PasswordService>;
    registrationService = new UserRegistrationService(mockUserRepository, mockPasswordService);
  });

  describe('Email Validation', () => {
    it('should reject empty email', async () => {
      const userData = {
        email: '',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Email is required');
    });

    it('should reject invalid email format', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(false);
      
      const userData = {
        email: 'invalid-email',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Invalid email format');
    });

    it('should accept valid email format', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockPasswordService.hashPassword.mockResolvedValue('hashed-password');
      mockUserRepository.create.mockResolvedValue({
        id: '1',
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      const result = await registrationService.register(userData);
      
      expect(result).toBeDefined();
      expect(result.email).toBe('test@example.com');
      expect(validator.isEmail).toHaveBeenCalledWith('test@example.com');
    });

    it('should reject email with invalid characters', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(false);

      const userData = {
        email: 'test@<script>alert(1)</script>.com',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Invalid email format');
    });

    it('should reject email longer than 254 characters', async () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      
      const userData = {
        email: longEmail,
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Email too long');
    });
  });

  describe('Duplicate Email Prevention', () => {
    it('should reject registration with existing email', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue({
        id: '1',
        email: 'existing@example.com',
        username: 'existing',
        passwordHash: 'hash',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const userData = {
        email: 'existing@example.com',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Email already registered');
    });

    it('should handle case-insensitive email duplicates', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue({
        id: '1',
        email: 'test@example.com',
        username: 'existing',
        passwordHash: 'hash',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const userData = {
        email: 'TEST@EXAMPLE.COM',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Email already registered');
      
      expect(mockUserRepository.findByEmail)
        .toHaveBeenCalledWith('test@example.com');
    });
  });

  describe('Username Validation', () => {
    it('should reject empty username', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: ''
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Username is required');
    });

    it('should reject username shorter than 3 characters', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'ab'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Username must be at least 3 characters long');
    });

    it('should reject username longer than 30 characters', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'a'.repeat(31)
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Username must be no more than 30 characters long');
    });

    it('should reject username with invalid characters', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'test@user!'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Username can only contain letters, numbers, and underscores');
    });

    it('should accept valid username', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.findByUsername.mockResolvedValue(null);
      mockPasswordService.hashPassword.mockResolvedValue('hashed-password');
      mockUserRepository.create.mockResolvedValue({
        id: '1',
        email: 'test@example.com',
        username: 'valid_user123',
        passwordHash: 'hashed-password',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'valid_user123'
      };

      const result = await registrationService.register(userData);
      expect(result.username).toBe('valid_user123');
    });
  });

  describe('Password Requirements', () => {
    beforeEach(() => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.findByUsername.mockResolvedValue(null);
    });

    it('should reject password shorter than 8 characters', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'Short1!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password must be at least 8 characters long');
    });

    it('should reject password without uppercase letter', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password must contain at least one uppercase letter');
    });

    it('should reject password without lowercase letter', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'PASSWORD123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password must contain at least one lowercase letter');
    });

    it('should reject password without number', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'Password!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password must contain at least one number');
    });

    it('should reject password without special character', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'Password123',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password must contain at least one special character');
    });

    it('should reject common passwords', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'Password123!',
        username: 'testuser'
      };

      await expect(registrationService.register(userData))
        .rejects
        .toThrow('Password is too common');
    });
  });

  describe('Successful Registration', () => {
    it('should successfully register user with valid data', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.findByUsername.mockResolvedValue(null);
      mockPasswordService.hashPassword.mockResolvedValue('hashed-password');
      
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password',
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      mockUserRepository.create.mockResolvedValue(mockUser);

      const userData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      const result = await registrationService.register(userData);

      expect(result).toEqual({
        id: '1',
        email: 'test@example.com',
        username: 'testuser',
        createdAt: expect.any(Date)
      });
      
      expect(mockPasswordService.hashPassword).toHaveBeenCalledWith('ValidPassword123!');
      expect(mockUserRepository.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password'
      });
    });

    it('should normalize email to lowercase before storage', async () => {
      (validator.isEmail as jest.Mock).mockReturnValue(true);
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.findByUsername.mockResolvedValue(null);
      mockPasswordService.hashPassword.mockResolvedValue('hashed-password');
      mockUserRepository.create.mockResolvedValue({
        id: '1',
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const userData = {
        email: 'TEST@EXAMPLE.COM',
        password: 'ValidPassword123!',
        username: 'testuser'
      };

      await registrationService.register(userData);

      expect(mockUserRepository.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password'
      });
    });
  });
});