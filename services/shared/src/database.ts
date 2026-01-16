import { Pool, PoolClient, QueryResult } from 'pg';
import { config } from './config';
import logger from './logger';

class Database {
  private pool: Pool | null = null;

  constructor() {
    this.pool = new Pool({
      host: config.database.host,
      port: config.database.port,
      database: config.database.name,
      user: config.database.user,
      password: config.database.password,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    this.pool.on('error', (err) => {
      logger.error(`Unexpected database error: ${err.message}`);
    });

    this.pool.on('connect', () => {
      logger.info('Database connection established');
    });
  }

  async query<T = any>(text: string, params?: any[]): Promise<QueryResult<T>> {
    const start = Date.now();
    try {
      const result = await this.pool!.query<T>(text, params);
      const duration = Date.now() - start;
      logger.debug(`Executed query: ${text} (${duration}ms)`);
      return result;
    } catch (error) {
      logger.error(`Database query error: ${error}`);
      throw error;
    }
  }

  async getClient(): Promise<PoolClient> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }
    return await this.pool.connect();
  }

  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      logger.info('Database connection pool closed');
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.query('SELECT 1');
      return result.rowCount === 1;
    } catch (error) {
      logger.error(`Database health check failed: ${error}`);
      return false;
    }
  }
}

export const database = new Database();
export default database;
