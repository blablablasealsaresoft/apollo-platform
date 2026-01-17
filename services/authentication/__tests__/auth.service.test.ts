import { authService } from '../src/services/auth.service';
import { database, redis } from '@apollo/shared';

// Mock bcrypt
jest.mock('bcrypt', () => ({
  hash: jest.fn(() => Promise.resolve('$2b$12$mockedHashedPassword')),
  compare: jest.fn(() => Promise.resolve(false)),
}));

// Mock jsonwebtoken
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mock.jwt.token'),
  verify: jest.fn(() => ({ userId: 'test-uuid', email: 'test@example.com' })),
}));

jest.mock('@apollo/shared', () => ({
  database: {
    query: jest.fn(),
  },
  redis: {
    set: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
  },
  config: {
    jwt: {
      secret: 'test-secret',
      accessExpiration: '15m',
      refreshExpiration: '7d',
    },
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
  generateId: jest.fn(() => 'test-uuid'),
  generateToken: jest.fn(() => 'test-token'),
  UserRole: { VIEWER: 'viewer', ADMIN: 'admin', ANALYST: 'analyst', INVESTIGATOR: 'investigator' },
  ClearanceLevel: { UNCLASSIFIED: 'unclassified', CONFIDENTIAL: 'confidential', SECRET: 'secret', TOP_SECRET: 'top_secret' },
  User: {},
  JWTPayload: {},
  UnauthorizedError: class UnauthorizedError extends Error {
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'UnauthorizedError';
    }
  },
  NotFoundError: class NotFoundError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'NotFoundError';
    }
  },
  ConflictError: class ConflictError extends Error {
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'ConflictError';
    }
  },
  InternalServerError: class InternalServerError extends Error {
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'InternalServerError';
    }
  },
  ServiceUnavailableError: class ServiceUnavailableError extends Error {
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'ServiceUnavailableError';
    }
  },
  BadRequestError: class BadRequestError extends Error {
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'BadRequestError';
    }
  },
}));

describe('AuthService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      const mockUser = {
        id: 'test-uuid',
        email: 'test@example.com',
        username: 'testuser',
        firstName: 'Test',
        lastName: 'User',
        role: 'viewer',
        clearanceLevel: 'unclassified',
        isActive: true,
        isMfaEnabled: false,
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // Check existing user
        .mockResolvedValueOnce({ rows: [mockUser] }); // Create user

      const userData = {
        email: 'test@example.com',
        username: 'testuser',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
      };

      const result = await authService.register(userData);

      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should throw error if user already exists', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ id: 'existing-user' }],
      });

      const userData = {
        email: 'existing@example.com',
        username: 'existing',
        password: 'SecurePass123!',
        firstName: 'Existing',
        lastName: 'User',
      };

      await expect(authService.register(userData)).rejects.toThrow();
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      const mockUser = {
        id: 'test-uuid',
        email: 'test@example.com',
        passwordHash: '$2b$12$mockedHashedPassword',
        isActive: true,
        isMfaEnabled: false,
        role: 'viewer',
        clearanceLevel: 'unclassified',
        firstName: 'Test',
        lastName: 'User',
        username: 'testuser',
      };

      // Mock bcrypt.compare to return true for this test
      const bcrypt = require('bcrypt');
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(true);

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockUser] }) // Find user
        .mockResolvedValue({ rows: [] }); // Activity log

      const result = await authService.login('test@example.com', 'TestPassword123!', '127.0.0.1');

      expect(result.user).toBeDefined();
      expect(result.requiresMfa).toBe(false);
    });

    it('should throw error for invalid credentials', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        authService.login('invalid@example.com', 'wrongpass', '127.0.0.1'),
      ).rejects.toThrow();
    });
  });
});
