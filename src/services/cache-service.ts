export class CacheService {
  private cache = new Map<string, { value: any; expires: number }>();

  async get(key: string): Promise<any> {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }

  async set(key: string, value: any, ttlSeconds: number): Promise<void> {
    const expires = Date.now() + (ttlSeconds * 1000);
    this.cache.set(key, { value, expires });
  }

  async increment(key: string): Promise<number> {
    const current = await this.get(key) || 0;
    const newValue = current + 1;
    await this.set(key, newValue, 900); // 15 minutes default TTL
    return newValue;
  }

  async mget(keys: string[]): Promise<any[]> {
    return Promise.all(keys.map(key => this.get(key)));
  }

  async deletePattern(pattern: string): Promise<void> {
    const regex = new RegExp(pattern.replace('*', '.*'));
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
      }
    }
  }

  async deleteExpired(): Promise<void> {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expires) {
        this.cache.delete(key);
      }
    }
  }

  // Enhanced methods for distributed systems support
  async getServerTime(): Promise<number> {
    // In a real Redis implementation, this would sync with server time
    return Date.now();
  }

  async acquireLock(lockKey: string, timeoutMs: number): Promise<boolean> {
    // Simple in-memory lock implementation
    const lockExists = this.cache.has(lockKey);
    if (lockExists) {
      return false;
    }

    this.cache.set(lockKey, { 
      value: 'locked', 
      expires: Date.now() + timeoutMs 
    });
    return true;
  }

  async releaseLock(lockKey: string): Promise<boolean> {
    return this.cache.delete(lockKey);
  }
}