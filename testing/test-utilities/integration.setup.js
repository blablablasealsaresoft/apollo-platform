// Integration test setup
const { Pool } = require('pg');
const Redis = require('ioredis');

// Database connection for integration tests
let dbPool;
let redisClient;

beforeAll(async () => {
  // Setup PostgreSQL connection
  dbPool = new Pool({
    host: process.env.TEST_DB_HOST || 'localhost',
    port: process.env.TEST_DB_PORT || 5432,
    database: process.env.TEST_DB_NAME || 'apollo_test',
    user: process.env.TEST_DB_USER || 'postgres',
    password: process.env.TEST_DB_PASSWORD || 'postgres',
  });

  // Setup Redis connection
  redisClient = new Redis({
    host: process.env.TEST_REDIS_HOST || 'localhost',
    port: process.env.TEST_REDIS_PORT || 6379,
    db: process.env.TEST_REDIS_DB || 15, // Use separate DB for tests
  });

  // Wait for connections
  await dbPool.query('SELECT 1');
  await redisClient.ping();

  console.log('Integration test databases connected');
});

afterAll(async () => {
  // Cleanup and close connections
  if (dbPool) {
    await dbPool.end();
  }
  if (redisClient) {
    await redisClient.quit();
  }
});

// Make available globally
global.testDb = dbPool;
global.testRedis = redisClient;

// Helper: Clear all test data
global.clearTestData = async () => {
  await dbPool.query('TRUNCATE TABLE investigations, targets, evidence, users CASCADE');
  await redisClient.flushdb();
};

// Helper: Seed test data
global.seedTestData = async () => {
  // Insert test users
  await dbPool.query(`
    INSERT INTO users (id, email, role, department, clearance_level)
    VALUES
      ('test-user-1', 'analyst@test.com', 'ANALYST', 'INVESTIGATIONS', 'SECRET'),
      ('test-user-2', 'admin@test.com', 'ADMIN', 'ADMINISTRATION', 'TOP_SECRET')
  `);

  // Insert test investigations
  await dbPool.query(`
    INSERT INTO investigations (id, case_number, title, priority, status, classification, created_by)
    VALUES
      ('test-inv-1', 'CASE-2026-0001', 'Test Case Alpha', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
  `);
};

// Run before each integration test
beforeEach(async () => {
  await global.clearTestData();
  await global.seedTestData();
});
