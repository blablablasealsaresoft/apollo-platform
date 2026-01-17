import request from 'supertest';

describe('Operations API Integration Tests', () => {
  let authToken: string;
  let testOperationId: string;
  let testUserId: string;
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3003/api';
  const AUTH_API_URL = process.env.AUTH_API_URL || 'http://localhost:3001/api';

  // Test operation data
  const testOperation = {
    name: 'Test Operation Alpha',
    codename: `ALPHA_${Date.now()}`,
    description: 'Integration test operation for API validation',
    priority: 'HIGH',
    clearanceLevel: 'CONFIDENTIAL',
    startDate: new Date().toISOString(),
  };

  beforeAll(async () => {
    // Get auth token
    const loginResponse = await request(AUTH_API_URL)
      .post('/auth/login')
      .send({
        email: process.env.TEST_USER_EMAIL || 'analyst@test.com',
        password: process.env.TEST_USER_PASSWORD || 'TestPassword123!',
      });

    authToken = loginResponse.body.data?.accessToken;
    testUserId = loginResponse.body.data?.user?.id;

    if (!authToken) {
      throw new Error('Failed to obtain auth token for operations tests');
    }

    // Health check
    const health = await request(API_BASE_URL).get('/health');
    if (health.status !== 200) {
      throw new Error('Operations service is not healthy');
    }
  });

  describe('POST /api/operations', () => {
    it('should create a new operation successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testOperation,
          leadInvestigatorId: testUserId,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.name).toBe(testOperation.name);
      expect(response.body.data.codename).toBe(testOperation.codename);
      expect(response.body.data.status).toBe('PLANNING');

      testOperationId = response.body.data.id;
    });

    it('should reject duplicate codename', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testOperation,
          leadInvestigatorId: testUserId,
        })
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('OPERATION_DUPLICATE_CODENAME');
    });

    it('should reject missing required fields', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Incomplete Operation',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('OPERATION_INVALID_DATA');
    });

    it('should reject unauthenticated requests', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .send(testOperation)
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should validate priority values', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testOperation,
          codename: `TEST_${Date.now()}`,
          priority: 'INVALID_PRIORITY',
          leadInvestigatorId: testUserId,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/operations/:id', () => {
    it('should retrieve operation by ID', async () => {
      const response = await request(API_BASE_URL)
        .get(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(testOperationId);
      expect(response.body.data.name).toBe(testOperation.name);
    });

    it('should return 404 for non-existent operation', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('OPERATION_NOT_FOUND');
    });

    it('should reject unauthenticated requests', async () => {
      await request(API_BASE_URL)
        .get(`/operations/${testOperationId}`)
        .expect(401);
    });
  });

  describe('GET /api/operations', () => {
    it('should list operations with pagination', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations')
        .query({ page: 1, limit: 10 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('operations');
      expect(response.body.data).toHaveProperty('total');
      expect(Array.isArray(response.body.data.operations)).toBe(true);
    });

    it('should filter operations by status', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations')
        .query({ status: 'PLANNING' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.operations.forEach((op: any) => {
        expect(op.status).toBe('PLANNING');
      });
    });

    it('should filter operations by priority', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations')
        .query({ priority: 'HIGH' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.operations.forEach((op: any) => {
        expect(op.priority).toBe('HIGH');
      });
    });

    it('should respect pagination limits', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations')
        .query({ limit: 5 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.operations.length).toBeLessThanOrEqual(5);
    });
  });

  describe('PUT /api/operations/:id', () => {
    it('should update operation successfully', async () => {
      const updates = {
        status: 'ACTIVE',
        description: 'Updated description for testing',
      };

      const response = await request(API_BASE_URL)
        .put(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updates)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe('ACTIVE');
      expect(response.body.data.description).toBe(updates.description);
    });

    it('should return 404 for non-existent operation', async () => {
      const response = await request(API_BASE_URL)
        .put('/operations/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ status: 'ACTIVE' })
        .expect(404);

      expect(response.body.error.code).toBe('OPERATION_NOT_FOUND');
    });

    it('should ignore disallowed fields', async () => {
      const response = await request(API_BASE_URL)
        .put(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          id: 'attempted-id-change',
          createdAt: '2020-01-01',
          leadInvestigatorId: 'attempted-change',
        })
        .expect(200);

      // ID should not change
      expect(response.body.data.id).toBe(testOperationId);
    });
  });

  describe('POST /api/operations/:id/team', () => {
    it('should assign team member to operation', async () => {
      const response = await request(API_BASE_URL)
        .post(`/operations/${testOperationId}/team`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ userId: testUserId })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should handle duplicate team member assignment gracefully', async () => {
      // Assigning same user again should not fail
      const response = await request(API_BASE_URL)
        .post(`/operations/${testOperationId}/team`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ userId: testUserId })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should validate required fields', async () => {
      const response = await request(API_BASE_URL)
        .post(`/operations/${testOperationId}/team`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('DELETE /api/operations/:id/team/:userId', () => {
    it('should remove team member from operation', async () => {
      const response = await request(API_BASE_URL)
        .delete(`/operations/${testOperationId}/team/${testUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should handle non-existent team member removal gracefully', async () => {
      const response = await request(API_BASE_URL)
        .delete(`/operations/${testOperationId}/team/non-existent-user`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('DELETE /api/operations/:id', () => {
    it('should delete operation successfully', async () => {
      const response = await request(API_BASE_URL)
        .delete(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should return 404 when deleting non-existent operation', async () => {
      const response = await request(API_BASE_URL)
        .delete(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.error.code).toBe('OPERATION_NOT_FOUND');
    });

    it('should verify operation is actually deleted', async () => {
      const response = await request(API_BASE_URL)
        .get(`/operations/${testOperationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.error.code).toBe('OPERATION_NOT_FOUND');
    });
  });

  describe('Error Handling', () => {
    it('should return proper error format for all errors', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations/invalid-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body).toHaveProperty('requestId');
    });

    it('should handle malformed JSON gracefully', async () => {
      const response = await request(API_BASE_URL)
        .post('/operations')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Content-Type', 'application/json')
        .send('{ invalid json }')
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Authorization', () => {
    it('should reject requests with expired tokens', async () => {
      // Using a fake expired token
      const response = await request(API_BASE_URL)
        .get('/operations')
        .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjB9.fake')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject requests with malformed tokens', async () => {
      const response = await request(API_BASE_URL)
        .get('/operations')
        .set('Authorization', 'Bearer not-a-valid-jwt')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
