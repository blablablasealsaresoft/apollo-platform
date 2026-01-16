import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';

describe('Intelligence API Integration Tests', () => {
  let authToken: string;
  let testReportIds: string[] = [];
  let testAuthorId: string;
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3004/api';
  const AUTH_API_URL = process.env.AUTH_API_URL || 'http://localhost:3001/api';

  // Test intelligence report data
  const testReport = {
    title: 'Test Intelligence Report',
    summary: 'Summary of intelligence findings for integration testing',
    content: 'Detailed content of the intelligence report including analysis and findings.',
    source: 'OSINT',
    confidence: 'HIGH',
    clearanceLevel: 'CONFIDENTIAL',
    tags: ['test', 'integration', 'automated'],
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
    testAuthorId = loginResponse.body.data?.user?.id;

    if (!authToken) {
      throw new Error('Failed to obtain auth token for intelligence tests');
    }

    // Health check
    const health = await request(API_BASE_URL).get('/health');
    if (health.status !== 200) {
      throw new Error('Intelligence service is not healthy');
    }
  });

  describe('POST /api/intelligence/reports', () => {
    it('should create a new intelligence report successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testReport,
          authorId: testAuthorId,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.title).toBe(testReport.title);
      expect(response.body.data.source).toBe(testReport.source);
      expect(response.body.data.confidence).toBe(testReport.confidence);

      testReportIds.push(response.body.data.id);
    });

    it('should reject missing required fields', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Incomplete Report',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INTEL_INVALID_DATA');
    });

    it('should reject invalid intelligence source', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testReport,
          source: 'INVALID_SOURCE',
          authorId: testAuthorId,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject invalid confidence level', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testReport,
          confidence: 'INVALID_CONFIDENCE',
          authorId: testAuthorId,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should sanitize tags array', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...testReport,
          title: 'Report with sanitized tags',
          tags: ['valid', 123, null, 'another-valid', { obj: 'should be filtered' }],
          authorId: testAuthorId,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      testReportIds.push(response.body.data.id);
    });

    it('should reject unauthenticated requests', async () => {
      await request(API_BASE_URL)
        .post('/intelligence/reports')
        .send(testReport)
        .expect(401);
    });

    // Create additional reports for correlation tests
    it('should create multiple reports for correlation testing', async () => {
      const reports = [
        { ...testReport, title: 'Correlation Test Report 1', tags: ['crypto', 'fraud', 'test'] },
        { ...testReport, title: 'Correlation Test Report 2', tags: ['crypto', 'laundering', 'test'] },
        { ...testReport, title: 'Correlation Test Report 3', tags: ['fraud', 'laundering', 'test'] },
      ];

      for (const report of reports) {
        const response = await request(API_BASE_URL)
          .post('/intelligence/reports')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ ...report, authorId: testAuthorId })
          .expect(201);

        testReportIds.push(response.body.data.id);
      }

      expect(testReportIds.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe('GET /api/intelligence/reports/:id', () => {
    it('should retrieve report by ID', async () => {
      const reportId = testReportIds[0];
      const response = await request(API_BASE_URL)
        .get(`/intelligence/reports/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(reportId);
      expect(response.body.data).toHaveProperty('title');
      expect(response.body.data).toHaveProperty('content');
    });

    it('should return 404 for non-existent report', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INTEL_REPORT_NOT_FOUND');
    });

    it('should reject unauthenticated requests', async () => {
      await request(API_BASE_URL)
        .get(`/intelligence/reports/${testReportIds[0]}`)
        .expect(401);
    });
  });

  describe('GET /api/intelligence/reports', () => {
    it('should list reports with pagination', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports')
        .query({ limit: 10, offset: 0 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('reports');
      expect(response.body.data).toHaveProperty('total');
      expect(Array.isArray(response.body.data.reports)).toBe(true);
    });

    it('should filter reports by source', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports')
        .query({ source: 'OSINT' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.reports.forEach((report: any) => {
        expect(report.source).toBe('OSINT');
      });
    });

    it('should filter reports by confidence', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports')
        .query({ confidence: 'HIGH' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.reports.forEach((report: any) => {
        expect(report.confidence).toBe('HIGH');
      });
    });

    it('should reject invalid source filter', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports')
        .query({ source: 'INVALID' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should respect pagination limits', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports')
        .query({ limit: 2 })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.reports.length).toBeLessThanOrEqual(2);
    });
  });

  describe('POST /api/intelligence/reports/correlate', () => {
    it('should correlate reports based on common tags', async () => {
      // Use reports created in earlier tests
      const reportIds = testReportIds.slice(-3); // Last 3 reports created for correlation

      const response = await request(API_BASE_URL)
        .post('/intelligence/reports/correlate')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ reportIds })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('correlations');
      expect(response.body.data).toHaveProperty('summary');
      expect(response.body.data.summary).toHaveProperty('totalCorrelations');
    });

    it('should reject correlation with less than 2 reports', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports/correlate')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ reportIds: [testReportIds[0]] })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INTEL_INSUFFICIENT_REPORTS');
    });

    it('should reject correlation with non-existent reports', async () => {
      const response = await request(API_BASE_URL)
        .post('/intelligence/reports/correlate')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ reportIds: ['non-existent-1', 'non-existent-2'] })
        .expect(404);

      expect(response.body.success).toBe(false);
    });

    it('should enforce maximum report limit', async () => {
      // Create array of 51 fake IDs
      const tooManyIds = Array(51).fill('fake-id');

      const response = await request(API_BASE_URL)
        .post('/intelligence/reports/correlate')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ reportIds: tooManyIds })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/intelligence/reports/:id/confidence', () => {
    it('should return confidence score for report', async () => {
      const reportId = testReportIds[0];
      const response = await request(API_BASE_URL)
        .get(`/intelligence/reports/${reportId}/confidence`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('score');
      expect(response.body.data).toHaveProperty('level');
      expect(response.body.data).toHaveProperty('description');
      expect(typeof response.body.data.score).toBe('number');
      expect(response.body.data.score).toBeGreaterThanOrEqual(0);
      expect(response.body.data.score).toBeLessThanOrEqual(1);
    });

    it('should return 404 for non-existent report', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports/non-existent-id/confidence')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
    });
  });

  describe('PUT /api/intelligence/reports/:id', () => {
    it('should update report successfully', async () => {
      const reportId = testReportIds[0];
      const updates = {
        title: 'Updated Intelligence Report Title',
        confidence: 'VERIFIED',
      };

      const response = await request(API_BASE_URL)
        .put(`/intelligence/reports/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updates)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(updates.title);
      expect(response.body.data.confidence).toBe(updates.confidence);
    });

    it('should return 404 for non-existent report', async () => {
      const response = await request(API_BASE_URL)
        .put('/intelligence/reports/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ title: 'Updated' })
        .expect(404);

      expect(response.body.success).toBe(false);
    });

    it('should handle empty update gracefully', async () => {
      const reportId = testReportIds[0];
      const response = await request(API_BASE_URL)
        .put(`/intelligence/reports/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({})
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('DELETE /api/intelligence/reports/:id', () => {
    it('should delete report successfully', async () => {
      const reportId = testReportIds.pop()!;
      const response = await request(API_BASE_URL)
        .delete(`/intelligence/reports/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should return 404 for non-existent report', async () => {
      const response = await request(API_BASE_URL)
        .delete('/intelligence/reports/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
    });

    it('should verify report is actually deleted', async () => {
      // Try to get the deleted report
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports/deleted-report-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should return consistent error format', async () => {
      const response = await request(API_BASE_URL)
        .get('/intelligence/reports/invalid-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body).toHaveProperty('timestamp');
    });
  });

  // Cleanup
  afterAll(async () => {
    // Delete all test reports
    for (const reportId of testReportIds) {
      try {
        await request(API_BASE_URL)
          .delete(`/intelligence/reports/${reportId}`)
          .set('Authorization', `Bearer ${authToken}`);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  });
});
