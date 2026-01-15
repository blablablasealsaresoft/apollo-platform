import { authService } from '../src/services/auth.service';
import { database, redis } from '@apollo/shared';

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
  },
  generateId: jest.fn(() => 'test-uuid'),
  UserRole: { VIEWER: 'viewer' },
  ClearanceLevel: { UNCLASSIFIED: 'unclassified' },
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
        passwordHash: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5mALjKN2zp.Z2',
        isActive: true,
        isMfaEnabled: false,
        role: 'viewer',
        clearanceLevel: 'unclassified',
      };

      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await authService.login('test@example.com', 'Apollo@2026!', '127.0.0.1');

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
