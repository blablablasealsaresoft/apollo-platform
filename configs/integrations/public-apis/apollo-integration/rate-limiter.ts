/**
 * Rate Limiter - Manage API rate limits intelligently
 *
 * @module RateLimiter
 * @elite-engineering
 */

export class RateLimiter {
  private limits: Map<string, { tokens: number; max: number; refillRate: number; lastRefill: Date }>;
  private statistics: Map<string, { totalCalls: number; successfulCalls: number; failedCalls: number; avgResponseTime: number }>;

  constructor() {
    this.limits = new Map();
    this.statistics = new Map();
  }

  /**
   * Wait for rate limit slot to be available
   */
  async waitForSlot(apiId: string): Promise<void> {
    // Initialize rate limit if not exists
    if (!this.limits.has(apiId)) {
      this.limits.set(apiId, {
        tokens: 100,
        max: 100,
        refillRate: 1, // tokens per second
        lastRefill: new Date()
      });
    }

    const limit = this.limits.get(apiId)!;

    // Refill tokens based on time elapsed
    this.refillTokens(apiId);

    // Wait if no tokens available
    while (limit.tokens < 1) {
      await this.sleep(1000);
      this.refillTokens(apiId);
    }

    // Consume token
    limit.tokens -= 1;
  }

  private refillTokens(apiId: string): void {
    const limit = this.limits.get(apiId)!;
    const now = new Date();
    const elapsed = (now.getTime() - limit.lastRefill.getTime()) / 1000;
    const tokensToAdd = Math.floor(elapsed * limit.refillRate);

    if (tokensToAdd > 0) {
      limit.tokens = Math.min(limit.max, limit.tokens + tokensToAdd);
      limit.lastRefill = now;
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  getStatistics(apiId: string): any {
    return this.statistics.get(apiId) || {
      totalCalls: 0,
      successfulCalls: 0,
      failedCalls: 0,
      avgResponseTime: 0
    };
  }
}

export const rateLimiter = new RateLimiter();
