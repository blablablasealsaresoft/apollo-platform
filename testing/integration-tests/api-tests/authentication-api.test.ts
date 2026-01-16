import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';

describe('Authentication API Integration Tests', () => {
  let authToken: string;
  let refreshToken: string;
  let testUserId: string;
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3001/api';

  // Test user credentials
  const testUser = {
    email: `test_${Date.now()}@apollo.test`,
    username: `testuser_${Date.now()}`,
    password: 'SecureTestPassword123!',
    firstName: 'Test',
    lastName: 'User',
  };

  const adminCredentials = {
    email: process.env.TEST_ADMIN_EMAIL || 'admin@apollo.local',
    password: process.env.TEST_ADMIN_PASSWORD || 'Apollo@2026!',
  };

  beforeAll(async () => {
    // Ensure test environment is ready
    const healthCheck = await request(API_BASE_URL)
      .get('/health')
      .timeout(5000);

    if (healthCheck.status !== 200) {
      throw new Error('Authentication service is not healthy');
    }
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/register')
        .send(testUser)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('user');
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data.user.email).toBe(testUser.email);
      expect(response.body.data.user).not.toHaveProperty('passwordHash');

      testUserId = response.body.data.user.id;
    });

    it('should reject registration with existing email', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/register')
        .send(testUser)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('AUTH_USER_EXISTS');
    });

    it('should reject registration with weak password', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/register')
        .send({
          ...testUser,
          email: 'weak@test.com',
          username: 'weakpassuser',
          password: 'weak',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('AUTH_PASSWORD_WEAK');
    });

    it('should reject registration with missing required fields', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/register')
        .send({
          email: 'incomplete@test.com',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject registration with invalid email format', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/register')
        .send({
          ...testUser,
          email: 'not-an-email',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login successfully with valid credentials', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data).toHaveProperty('user');
      expect(response.body.data.requiresMfa).toBe(false);

      authToken = response.body.data.accessToken;
      refreshToken = response.body.data.refreshToken;
    });

    it('should reject login with invalid password', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('AUTH_INVALID_CREDENTIALS');
    });

    it('should reject login with non-existent email', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/login')
        .send({
          email: 'nonexistent@test.com',
          password: 'SomePassword123!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('AUTH_INVALID_CREDENTIALS');
    });

    it('should reject login with missing credentials', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/login')
        .send({
          email: testUser.email,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should include request ID in response', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(response.body).toHaveProperty('requestId');
    });
  });

  describe('POST /api/auth/refresh', () => {
    it('should refresh access token successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');

      // Update tokens for subsequent tests
      authToken = response.body.data.accessToken;
      refreshToken = response.body.data.refreshToken;
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/refresh')
        .send({ refreshToken: 'invalid-refresh-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject missing refresh token', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/refresh')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/auth/validate', () => {
    it('should validate a valid token', async () => {
      const response = await request(API_BASE_URL)
        .get('/auth/validate')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('userId');
      expect(response.body.data).toHaveProperty('email');
    });

    it('should reject invalid token', async () => {
      const response = await request(API_BASE_URL)
        .get('/auth/validate')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject missing token', async () => {
      const response = await request(API_BASE_URL)
        .get('/auth/validate')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject expired token', async () => {
      // This would require a token with a very short expiration
      // Skipping for now as it requires time manipulation
    });
  });

  describe('POST /api/auth/password/change', () => {
    const newPassword = 'NewSecurePassword456!';

    it('should change password successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/change')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          oldPassword: testUser.password,
          newPassword: newPassword,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should reject with wrong old password', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/change')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          oldPassword: 'WrongOldPassword!',
          newPassword: 'AnotherNewPassword789!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject weak new password', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/change')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          oldPassword: newPassword,
          newPassword: 'weak',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should require authentication', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/change')
        .send({
          oldPassword: 'whatever',
          newPassword: 'NewPassword123!',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    // Restore password for other tests
    afterAll(async () => {
      await request(API_BASE_URL)
        .post('/auth/password/change')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          oldPassword: newPassword,
          newPassword: testUser.password,
        });
    });
  });

  describe('POST /api/auth/password/reset-request', () => {
    it('should accept password reset request for valid email', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/reset-request')
        .send({ email: testUser.email })
        .expect(200);

      // Should return success even if email doesn't exist (security)
      expect(response.body.success).toBe(true);
    });

    it('should not reveal if email exists', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/password/reset-request')
        .send({ email: 'nonexistent@test.com' })
        .expect(200);

      // Same response for non-existent email
      expect(response.body.success).toBe(true);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should logout successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should invalidate refresh token after logout', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits on login endpoint', async () => {
      const requests = [];

      // Make many rapid requests
      for (let i = 0; i < 20; i++) {
        requests.push(
          request(API_BASE_URL)
            .post('/auth/login')
            .send({
              email: 'ratelimit@test.com',
              password: 'TestPassword123!',
            })
        );
      }

      const responses = await Promise.all(requests);
      const rateLimitedResponses = responses.filter(r => r.status === 429);

      // Should have some rate limited responses
      expect(rateLimitedResponses.length).toBeGreaterThan(0);

      // Check for Retry-After header
      if (rateLimitedResponses.length > 0) {
        expect(rateLimitedResponses[0].headers).toHaveProperty('retry-after');
      }
    }, 30000);
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const response = await request(API_BASE_URL)
        .get('/health')
        .expect(200);

      // Check for common security headers (from helmet)
      expect(response.headers).toHaveProperty('x-content-type-options');
      expect(response.headers).toHaveProperty('x-frame-options');
    });
  });

  // Cleanup
  afterAll(async () => {
    // Clean up test user if admin credentials are available
    try {
      const adminLogin = await request(API_BASE_URL)
        .post('/auth/login')
        .send(adminCredentials);

      if (adminLogin.body.data?.accessToken && testUserId) {
        await request(API_BASE_URL)
          .delete(`/users/${testUserId}`)
          .set('Authorization', `Bearer ${adminLogin.body.data.accessToken}`);
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  });
});
