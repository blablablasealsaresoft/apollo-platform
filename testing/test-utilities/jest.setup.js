// Global Jest setup for all tests
const dotenv = require('dotenv');

// Load test environment variables
dotenv.config({ path: '.env.test' });

// Set test environment
process.env.NODE_ENV = 'test';

// Suppress console logs during tests (optional)
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Global test timeout
jest.setTimeout(30000);

// Mock external APIs
global.mockExternalAPIs = () => {
  // Mock OpenAI
  jest.mock('openai', () => ({
    OpenAI: jest.fn().mockImplementation(() => ({
      chat: {
        completions: {
          create: jest.fn().mockResolvedValue({
            choices: [{ message: { content: 'Mocked AI response' } }],
          }),
        },
      },
    })),
  }));

  // Mock AWS SDK
  jest.mock('aws-sdk', () => ({
    S3: jest.fn().mockImplementation(() => ({
      upload: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({ Location: 'https://s3.mock.url' }) }),
      getObject: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({ Body: Buffer.from('mock data') }) }),
    })),
  }));
};

// Database cleanup helper
global.cleanupDatabase = async () => {
  // Implement database cleanup logic
  // This will be called after each test suite
};

// Redis cleanup helper
global.cleanupRedis = async () => {
  // Implement Redis cleanup logic
};

// Mock data generators
global.generateMockUser = () => ({
  id: 'test-user-' + Date.now(),
  email: 'test@example.com',
  role: 'ANALYST',
  department: 'INVESTIGATIONS',
  clearanceLevel: 'SECRET',
});

global.generateMockInvestigation = () => ({
  id: 'inv-' + Date.now(),
  caseNumber: 'CASE-2026-' + Math.floor(Math.random() * 10000),
  title: 'Test Investigation',
  priority: 'HIGH',
  status: 'ACTIVE',
  classification: 'CONFIDENTIAL',
});

global.generateMockTarget = () => ({
  id: 'target-' + Date.now(),
  name: 'Test Target',
  type: 'PERSON',
  riskLevel: 'HIGH',
  status: 'ACTIVE',
});

// Cleanup after all tests
afterAll(async () => {
  await global.cleanupDatabase();
  await global.cleanupRedis();
});
