import { createClient, RedisClientType } from 'redis';
import { config } from './config';
import logger from './logger';

class RedisClient {
  private client: RedisClientType | null = null;
  private publisher: RedisClientType | null = null;
  private subscriber: RedisClientType | null = null;

  async connect(): Promise<void> {
    const redisConfig = {
      socket: {
        host: config.redis.host,
        port: config.redis.port,
      },
    };

    this.client = createClient(redisConfig);
    this.publisher = createClient(redisConfig);
    this.subscriber = createClient(redisConfig);

    this.client.on('error', (err) => logger.error(`Redis Client Error: ${err}`));
    this.publisher.on('error', (err) => logger.error(`Redis Publisher Error: ${err}`));
    this.subscriber.on('error', (err) => logger.error(`Redis Subscriber Error: ${err}`));

    await this.client.connect();
    await this.publisher.connect();
    await this.subscriber.connect();

    logger.info('Redis clients connected');
  }

  getClient(): RedisClientType {
    if (!this.client) {
      throw new Error('Redis client not initialized');
    }
    return this.client;
  }

  getPublisher(): RedisClientType {
    if (!this.publisher) {
      throw new Error('Redis publisher not initialized');
    }
    return this.publisher;
  }

  getSubscriber(): RedisClientType {
    if (!this.subscriber) {
      throw new Error('Redis subscriber not initialized');
    }
    return this.subscriber;
  }

  async set(key: string, value: string, expirationSeconds?: number): Promise<void> {
    const client = this.getClient();
    if (expirationSeconds) {
      await client.setEx(key, expirationSeconds, value);
    } else {
      await client.set(key, value);
    }
  }

  async get(key: string): Promise<string | null> {
    const client = this.getClient();
    return await client.get(key);
  }

  async del(key: string): Promise<void> {
    const client = this.getClient();
    await client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const client = this.getClient();
    const result = await client.exists(key);
    return result === 1;
  }

  async publish(channel: string, message: string): Promise<void> {
    const publisher = this.getPublisher();
    await publisher.publish(channel, message);
  }

  async subscribe(channel: string, callback: (message: string) => void): Promise<void> {
    const subscriber = this.getSubscriber();
    await subscriber.subscribe(channel, callback);
  }

  async unsubscribe(channel: string): Promise<void> {
    const subscriber = this.getSubscriber();
    await subscriber.unsubscribe(channel);
  }

  async disconnect(): Promise<void> {
    if (this.client) await this.client.quit();
    if (this.publisher) await this.publisher.quit();
    if (this.subscriber) await this.subscriber.quit();
    logger.info('Redis clients disconnected');
  }

  async healthCheck(): Promise<boolean> {
    try {
      const client = this.getClient();
      const pong = await client.ping();
      return pong === 'PONG';
    } catch (error) {
      logger.error(`Redis health check failed: ${error}`);
      return false;
    }
  }
}

export const redis = new RedisClient();
export default redis;
