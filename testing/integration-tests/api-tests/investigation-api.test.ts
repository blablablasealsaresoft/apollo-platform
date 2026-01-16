import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';

describe('Investigation API Integration Tests', () => {
  let authToken: string;
  let testInvestigationId: string;
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api';

  beforeAll(async () => {
    // Login and get auth token
    const loginResponse = await request(API_BASE_URL)
      .post('/auth/login')
      .send({
        email: 'analyst@test.com',
        password: 'TestPassword123!',
      });

    authToken = loginResponse.body.token;
  });

  describe('POST /api/investigations', () => {
    it('should create new investigation with authentication', async () => {
      const response = await request(API_BASE_URL)
        .post('/investigations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          caseNumber: 'CASE-2026-TEST-001',
          title: 'Integration Test Investigation',
          description: 'Test case for API integration',
          priority: 'HIGH',
          classification: 'CONFIDENTIAL',
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.caseNumber).toBe('CASE-2026-TEST-001');
      testInvestigationId = response.body.id;
    });

    it('should reject unauthenticated requests', async () => {
      await request(API_BASE_URL)
        .post('/investigations')
        .send({
          title: 'Unauthorized Test',
        })
        .expect(401);
    });

    it('should validate required fields', async () => {
      const response = await request(API_BASE_URL)
        .post('/investigations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Missing Required Fields',
          // Missing priority and classification
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });
  });

  describe('GET /api/investigations/:id', () => {
    it('should retrieve investigation by id', async () => {
      const response = await request(API_BASE_URL)
        .get(`/investigations/${testInvestigationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.id).toBe(testInvestigationId);
      expect(response.body).toHaveProperty('caseNumber');
      expect(response.body).toHaveProperty('title');
    });

    it('should return 404 for non-existent investigation', async () => {
      await request(API_BASE_URL)
        .get('/investigations/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('PUT /api/investigations/:id', () => {
    it('should update investigation', async () => {
      const response = await request(API_BASE_URL)
        .put(`/investigations/${testInvestigationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          priority: 'CRITICAL',
          status: 'ACTIVE',
        })
        .expect(200);

      expect(response.body.priority).toBe('CRITICAL');
    });

    it('should maintain audit trail on update', async () => {
      const response = await request(API_BASE_URL)
        .get(`/investigations/${testInvestigationId}/history`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toBeInstanceOf(Array);
      expect(response.body.length).toBeGreaterThan(0);
    });
  });

  describe('GET /api/investigations', () => {
    it('should list investigations with pagination', async () => {
      const response = await request(API_BASE_URL)
        .get('/investigations')
        .query({ page: 1, limit: 10 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('pagination');
      expect(response.body.data).toBeInstanceOf(Array);
    });

    it('should filter investigations by priority', async () => {
      const response = await request(API_BASE_URL)
        .get('/investigations')
        .query({ priority: 'CRITICAL' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      response.body.data.forEach((inv: any) => {
        expect(inv.priority).toBe('CRITICAL');
      });
    });

    it('should search investigations by case number', async () => {
      const response = await request(API_BASE_URL)
        .get('/investigations')
        .query({ caseNumber: 'CASE-2026-TEST-001' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.length).toBeGreaterThan(0);
      expect(response.body.data[0].caseNumber).toBe('CASE-2026-TEST-001');
    });
  });

  describe('POST /api/investigations/:id/targets', () => {
    it('should add target to investigation', async () => {
      const response = await request(API_BASE_URL)
        .post(`/investigations/${testInvestigationId}/targets`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Test Target',
          type: 'PERSON',
          riskLevel: 'HIGH',
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.name).toBe('Test Target');
    });
  });

  describe('POST /api/investigations/:id/evidence', () => {
    it('should attach evidence to investigation', async () => {
      const response = await request(API_BASE_URL)
        .post(`/investigations/${testInvestigationId}/evidence`)
        .set('Authorization', `Bearer ${authToken}`)
        .field('description', 'Test evidence document')
        .field('type', 'DOCUMENT')
        .attach('file', Buffer.from('test file content'), 'test.pdf')
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.filename).toBe('test.pdf');
    });
  });

  describe('DELETE /api/investigations/:id', () => {
    it('should delete investigation', async () => {
      await request(API_BASE_URL)
        .delete(`/investigations/${testInvestigationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(204);

      // Verify deletion
      await request(API_BASE_URL)
        .get(`/investigations/${testInvestigationId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', async () => {
      const requests = [];
      for (let i = 0; i < 110; i++) {
        requests.push(
          request(API_BASE_URL)
            .get('/investigations')
            .set('Authorization', `Bearer ${authToken}`)
        );
      }

      const responses = await Promise.all(requests);
      const rateLimitedResponses = responses.filter(r => r.status === 429);

      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    }, 30000);
  });
});
