import request from 'supertest';
import app from '../src/index';
import { database, redis } from '@apollo/shared';

/**
 * Integration tests for the Authentication Service
 * These tests verify the full flow from HTTP request to database
 */
describe('Authentication Service Integration Tests', () => {
  let testUserEmail: string;
  let testUserToken: string;
  let testRefreshToken: string;
  let testUserId: string;

  beforeAll(async () => {
    // Generate unique test user email
    testUserEmail = `integration_test_${Date.now()}@apollo.test`;

    // Wait for database connection
    let retries = 5;
    while (retries > 0) {
      try {
        await database.query('SELECT 1');
        break;
      } catch (e) {
        retries--;
        if (retries === 0) throw new Error('Database not available');
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  });

  afterAll(async () => {
    // Cleanup test user
    if (testUserId) {
      try {
        await database.query('DELETE FROM users WHERE id = $1', [testUserId]);
        await redis.del(`refresh_token:${testUserId}`);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
    // Close connections
    await database.close();
    await redis.disconnect();
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.service).toBe('authentication');
      expect(response.body.checks).toHaveProperty('database');
      expect(response.body.checks).toHaveProperty('redis');
    });
  });

  describe('User Registration Flow', () => {
    it('should register a new user', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: testUserEmail,
          username: `testuser_${Date.now()}`,
          password: 'IntegrationTest123!',
          firstName: 'Integration',
          lastName: 'Test',
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(testUserEmail);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data.user).not.toHaveProperty('passwordHash');

      testUserId = response.body.data.user.id;
      testUserToken = response.body.data.accessToken;
      testRefreshToken = response.body.data.refreshToken;
    });

    it('should verify user exists in database', async () => {
      const result = await database.query(
        'SELECT id, email, is_active FROM users WHERE email = $1',
        [testUserEmail]
      );

      expect(result.rows.length).toBe(1);
      expect(result.rows[0].email).toBe(testUserEmail);
      expect(result.rows[0].is_active).toBe(true);
    });

    it('should store refresh token in Redis', async () => {
      const storedToken = await redis.get(`refresh_token:${testUserId}`);
      expect(storedToken).toBe(testRefreshToken);
    });

    it('should reject duplicate registration', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: testUserEmail,
          username: 'different_username',
          password: 'AnotherPassword123!',
          firstName: 'Duplicate',
          lastName: 'Test',
        })
        .expect(409);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Login Flow', () => {
    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUserEmail,
          password: 'IntegrationTest123!',
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data.user.email).toBe(testUserEmail);

      // Update tokens for subsequent tests
      testUserToken = response.body.data.accessToken;
      testRefreshToken = response.body.data.refreshToken;
    });

    it('should update last_login timestamp', async () => {
      const result = await database.query(
        'SELECT last_login FROM users WHERE id = $1',
        [testUserId]
      );

      expect(result.rows[0].last_login).not.toBeNull();
    });

    it('should reject invalid password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUserEmail,
          password: 'WrongPassword!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject non-existent user', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@test.com',
          password: 'SomePassword123!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Token Validation Flow', () => {
    it('should validate a valid token', async () => {
      const response = await request(app)
        .get('/api/auth/validate')
        .set('Authorization', `Bearer ${testUserToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.userId).toBe(testUserId);
    });

    it('should reject invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/validate')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject missing authorization header', async () => {
      const response = await request(app)
        .get('/api/auth/validate')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Token Refresh Flow', () => {
    it('should refresh access token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: testRefreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');

      // Update tokens
      testUserToken = response.body.data.accessToken;
      testRefreshToken = response.body.data.refreshToken;
    });

    it('should update refresh token in Redis', async () => {
      const storedToken = await redis.get(`refresh_token:${testUserId}`);
      expect(storedToken).toBe(testRefreshToken);
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: 'invalid-refresh-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Password Change Flow', () => {
    const newPassword = 'NewIntegrationTest456!';

    it('should change password successfully', async () => {
      const response = await request(app)
        .post('/api/auth/password/change')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          oldPassword: 'IntegrationTest123!',
          newPassword: newPassword,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should login with new password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUserEmail,
          password: newPassword,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      testUserToken = response.body.data.accessToken;
      testRefreshToken = response.body.data.refreshToken;
    });

    it('should reject old password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUserEmail,
          password: 'IntegrationTest123!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject password change with wrong old password', async () => {
      const response = await request(app)
        .post('/api/auth/password/change')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          oldPassword: 'WrongOldPassword!',
          newPassword: 'AnotherNewPassword789!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Logout Flow', () => {
    it('should logout successfully', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({ refreshToken: testRefreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should remove refresh token from Redis', async () => {
      const storedToken = await redis.get(`refresh_token:${testUserId}`);
      expect(storedToken).toBeNull();
    });

    it('should reject refresh with invalidated token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: testRefreshToken })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Password Reset Flow', () => {
    it('should accept password reset request', async () => {
      const response = await request(app)
        .post('/api/auth/password/reset-request')
        .send({ email: testUserEmail })
        .expect(200);

      // Should always return success to prevent email enumeration
      expect(response.body.success).toBe(true);
    });

    it('should store reset token in database', async () => {
      const result = await database.query(
        'SELECT password_reset_token, password_reset_expires FROM users WHERE id = $1',
        [testUserId]
      );

      expect(result.rows[0].password_reset_token).not.toBeNull();
      expect(new Date(result.rows[0].password_reset_expires) > new Date()).toBe(true);
    });

    it('should not reveal non-existent email', async () => {
      const response = await request(app)
        .post('/api/auth/password/reset-request')
        .send({ email: 'nonexistent@test.com' })
        .expect(200);

      // Same response for non-existent email
      expect(response.body.success).toBe(true);
    });
  });

  describe('Activity Logging', () => {
    it('should log login activity', async () => {
      // First login
      await request(app)
        .post('/api/auth/login')
        .send({
          email: testUserEmail,
          password: 'NewIntegrationTest456!',
        });

      // Check activity log
      const result = await database.query(
        `SELECT action FROM activity_logs
         WHERE user_id = $1 AND action = 'USER_LOGIN'
         ORDER BY timestamp DESC LIMIT 1`,
        [testUserId]
      );

      expect(result.rows.length).toBeGreaterThan(0);
      expect(result.rows[0].action).toBe('USER_LOGIN');
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      // This test would require mocking database failures
      // Skipping for now as it requires more setup
    });

    it('should include request ID in all responses', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'any@email.com',
          password: 'anypassword',
        });

      expect(response.body).toHaveProperty('requestId');
    });

    it('should not leak stack traces in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const response = await request(app)
        .post('/api/auth/login')
        .send({});

      expect(response.body.error).not.toHaveProperty('stack');

      process.env.NODE_ENV = originalEnv;
    });
  });
});
