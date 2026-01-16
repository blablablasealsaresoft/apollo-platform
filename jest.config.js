module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/testing', '<rootDir>/services'],
  testMatch: [
    '**/__tests__/**/*.+(ts|tsx|js)',
    '**/?(*.)+(spec|test).+(ts|tsx|js)'
  ],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
  },
  collectCoverageFrom: [
    'services/**/*.{js,ts}',
    'ai-engine/**/*.{js,ts}',
    'intelligence/**/*.{js,ts}',
    'frontend/**/*.{js,ts,tsx}',
    '!**/*.d.ts',
    '!**/node_modules/**',
    '!**/dist/**',
    '!**/build/**',
    '!**/*.config.js',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@services/(.*)$': '<rootDir>/services/$1',
    '^@ai-engine/(.*)$': '<rootDir>/ai-engine/$1',
    '^@intelligence/(.*)$': '<rootDir>/intelligence/$1',
    '^@frontend/(.*)$': '<rootDir>/frontend/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/testing/test-utilities/jest.setup.js'],
  testTimeout: 30000,
  maxWorkers: '50%',
  verbose: true,
  projects: [
    {
      displayName: 'unit',
      testMatch: ['<rootDir>/testing/unit-tests/**/*.test.{ts,tsx,js}'],
      testEnvironment: 'node',
    },
    {
      displayName: 'services',
      testMatch: ['<rootDir>/services/**/__tests__/**/*.test.{ts,tsx,js}'],
      testEnvironment: 'node',
      moduleNameMapper: {
        '^@apollo/shared$': '<rootDir>/services/shared/src',
        '^@apollo/shared/(.*)$': '<rootDir>/services/shared/src/$1',
      },
    },
    {
      displayName: 'integration',
      testMatch: ['<rootDir>/testing/integration-tests/**/*.test.{ts,tsx,js}'],
      testEnvironment: 'node',
      setupFilesAfterEnv: ['<rootDir>/testing/test-utilities/integration.setup.js'],
    },
    {
      displayName: 'frontend',
      testMatch: ['<rootDir>/testing/unit-tests/frontend/**/*.test.{ts,tsx,js}'],
      testEnvironment: 'jsdom',
      setupFilesAfterEnv: ['<rootDir>/testing/test-utilities/frontend.setup.js'],
    },
  ],
};
