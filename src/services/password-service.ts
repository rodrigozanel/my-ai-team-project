import bcrypt from 'bcrypt';

export class PasswordService {
  private readonly defaultSaltRounds = 12;

  async hashPassword(password: string, saltRounds?: number): Promise<string> {
    if (!password) {
      throw new Error('Password cannot be empty');
    }

    try {
      const rounds = saltRounds ?? this.defaultSaltRounds;
      return await bcrypt.hash(password, rounds);
    } catch (error) {
      throw new Error('Password hashing failed');
    }
  }

  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    if (!plainPassword) {
      throw new Error('Plain password cannot be empty');
    }

    if (!hashedPassword) {
      throw new Error('Hashed password cannot be empty');
    }

    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      throw new Error('Password verification failed');
    }
  }
}