import validator from 'validator';
import { UserRepository } from '../repositories/user-repository';
import { PasswordService } from './password-service';
import { RegistrationData, RegistrationResponse } from '../types';

export class UserRegistrationService {
  private commonPasswords = new Set([
    'Password123!',
    'password123',
    '123456789',
    'qwerty123'
  ]);

  constructor(
    private userRepository: UserRepository,
    private passwordService: PasswordService
  ) {}

  async register(userData: RegistrationData): Promise<RegistrationResponse> {
    await this.validateRegistrationData(userData);

    const normalizedEmail = userData.email.toLowerCase();
    
    // Check for existing email
    const existingUser = await this.userRepository.findByEmail(normalizedEmail);
    if (existingUser) {
      throw new Error('Email already registered');
    }

    // Check for existing username
    const existingUsername = await this.userRepository.findByUsername(userData.username);
    if (existingUsername) {
      throw new Error('Username already taken');
    }

    // Hash password
    const passwordHash = await this.passwordService.hashPassword(userData.password);

    // Create user
    const user = await this.userRepository.create({
      email: normalizedEmail,
      username: userData.username,
      passwordHash
    });

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      createdAt: user.createdAt
    };
  }

  private async validateRegistrationData(userData: RegistrationData): Promise<void> {
    // Email validation
    if (!userData.email) {
      throw new Error('Email is required');
    }

    if (userData.email.length > 254) {
      throw new Error('Email too long');
    }

    if (!validator.isEmail(userData.email)) {
      throw new Error('Invalid email format');
    }

    // Username validation
    if (!userData.username) {
      throw new Error('Username is required');
    }

    if (userData.username.length < 3) {
      throw new Error('Username must be at least 3 characters long');
    }

    if (userData.username.length > 30) {
      throw new Error('Username must be no more than 30 characters long');
    }

    if (!/^[a-zA-Z0-9_]+$/.test(userData.username)) {
      throw new Error('Username can only contain letters, numbers, and underscores');
    }

    // Password validation
    await this.validatePassword(userData.password);
  }

  private async validatePassword(password: string): Promise<void> {
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

    if (this.commonPasswords.has(password)) {
      throw new Error('Password is too common');
    }
  }
}