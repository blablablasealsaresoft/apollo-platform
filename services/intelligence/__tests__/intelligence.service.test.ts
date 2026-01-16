/**
 * Intelligence Service Unit Tests
 * Tests for intelligence report CRUD, correlation, and confidence scoring
 */

import { IntelligenceService, INTELLIGENCE_ERROR_CODES } from '../src/services/intelligence.service';

// Mock dependencies
jest.mock('@apollo/shared', () => ({
  database: {
    query: jest.fn(),
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  generateId: jest.fn(() => 'test-report-id-12345'),
  NotFoundError: class NotFoundError extends Error {
    code: string;
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'NotFoundError';
      this.code = code || 'NOT_FOUND';
    }
  },
  BadRequestError: class BadRequestError extends Error {
    code: string;
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'BadRequestError';
      this.code = code || 'BAD_REQUEST';
    }
  },
  InternalServerError: class InternalServerError extends Error {
    code: string;
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'InternalServerError';
      this.code = code || 'INTERNAL_ERROR';
    }
  },
  ServiceUnavailableError: class ServiceUnavailableError extends Error {
    code: string;
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'ServiceUnavailableError';
      this.code = code || 'SERVICE_UNAVAILABLE';
    }
  },
  IntelligenceSource: {
    HUMINT: 'humint',
    SIGINT: 'sigint',
    OSINT: 'osint',
    GEOINT: 'geoint',
    FININT: 'finint',
    TECHINT: 'techint',
  },
  ConfidenceLevel: {
    VERIFIED: 'verified',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    UNCONFIRMED: 'unconfirmed',
  },
  ClearanceLevel: {
    TOP_SECRET: 'top_secret',
    SECRET: 'secret',
    CONFIDENTIAL: 'confidential',
    RESTRICTED: 'restricted',
    UNCLASSIFIED: 'unclassified',
  },
}));

import {
  database,
  NotFoundError,
  BadRequestError,
  InternalServerError,
  ServiceUnavailableError,
  IntelligenceSource,
  ConfidenceLevel,
  ClearanceLevel,
} from '@apollo/shared';

describe('IntelligenceService', () => {
  let intelligenceService: IntelligenceService;

  const mockReport = {
    id: 'report-123',
    title: 'Test Intelligence Report',
    summary: 'Test summary',
    content: 'Detailed intelligence content',
    source: IntelligenceSource.OSINT,
    confidence: ConfidenceLevel.HIGH,
    clearanceLevel: ClearanceLevel.SECRET,
    authorId: 'user-123',
    operationId: 'operation-123',
    targetId: 'target-123',
    tags: ['crypto', 'fraud'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(() => {
    intelligenceService = new IntelligenceService();
    jest.clearAllMocks();
  });

  describe('createReport', () => {
    const validData = {
      title: 'Test Report',
      summary: 'Test summary',
      content: 'Detailed content',
      source: IntelligenceSource.OSINT,
      confidence: ConfidenceLevel.HIGH,
      clearanceLevel: ClearanceLevel.SECRET,
      authorId: 'user-123',
      tags: ['tag1', 'tag2'],
    };

    it('should create report successfully', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mockReport] });

      const result = await intelligenceService.createReport(validData);

      expect(result).toHaveProperty('id');
      expect(result.title).toBe(mockReport.title);
    });

    it('should throw BadRequestError when title is empty', async () => {
      const invalidData = { ...validData, title: '' };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when title is whitespace', async () => {
      const invalidData = { ...validData, title: '   ' };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when summary is empty', async () => {
      const invalidData = { ...validData, summary: '' };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when content is empty', async () => {
      const invalidData = { ...validData, content: '' };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when authorId is missing', async () => {
      const invalidData = { ...validData, authorId: '' };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for invalid source', async () => {
      const invalidData = { ...validData, source: 'invalid' as IntelligenceSource };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for invalid confidence level', async () => {
      const invalidData = { ...validData, confidence: 'invalid' as ConfidenceLevel };

      await expect(intelligenceService.createReport(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should sanitize tags array', async () => {
      const dataWithMixedTags = {
        ...validData,
        tags: ['valid', 123, 'also-valid', null, undefined] as any[],
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mockReport] });

      await intelligenceService.createReport(dataWithMixedTags);

      const insertCall = (database.query as jest.Mock).mock.calls[0];
      const tagsArg = JSON.parse(insertCall[1][10]);
      expect(tagsArg).toEqual(['valid', 'also-valid']);
    });

    it('should handle optional operationId and targetId', async () => {
      const dataWithoutOptional = {
        ...validData,
        operationId: undefined,
        targetId: undefined,
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mockReport] });

      await intelligenceService.createReport(dataWithoutOptional);

      const insertCall = (database.query as jest.Mock).mock.calls[0];
      expect(insertCall[1]).toContain(null); // operationId
      expect(insertCall[1]).toContain(null); // targetId
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock).mockRejectedValueOnce(new Error('Database error'));

      await expect(intelligenceService.createReport(validData))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('getReportById', () => {
    it('should return report when found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mockReport] });

      const result = await intelligenceService.getReportById('report-123');

      expect(result).toEqual(mockReport);
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(intelligenceService.getReportById(''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when report not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(intelligenceService.getReportById('non-existent'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw ServiceUnavailableError on database failure', async () => {
      (database.query as jest.Mock).mockRejectedValueOnce(new Error('Connection failed'));

      await expect(intelligenceService.getReportById('report-123'))
        .rejects.toThrow(ServiceUnavailableError);
    });
  });

  describe('listReports', () => {
    const mockReports = [mockReport, { ...mockReport, id: 'report-456' }];

    it('should list reports without filters', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '2' }] })
        .mockResolvedValueOnce({ rows: mockReports });

      const result = await intelligenceService.listReports();

      expect(result.reports).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should filter by source', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockReport] });

      await intelligenceService.listReports({ source: IntelligenceSource.OSINT });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('AND source = $1'),
        expect.arrayContaining([IntelligenceSource.OSINT])
      );
    });

    it('should throw BadRequestError for invalid source filter', async () => {
      await expect(
        intelligenceService.listReports({ source: 'invalid' as IntelligenceSource })
      ).rejects.toThrow(BadRequestError);
    });

    it('should filter by confidence', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockReport] });

      await intelligenceService.listReports({ confidence: ConfidenceLevel.VERIFIED });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('AND confidence = $'),
        expect.arrayContaining([ConfidenceLevel.VERIFIED])
      );
    });

    it('should throw BadRequestError for invalid confidence filter', async () => {
      await expect(
        intelligenceService.listReports({ confidence: 'invalid' as ConfidenceLevel })
      ).rejects.toThrow(BadRequestError);
    });

    it('should filter by operationId', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockReport] });

      await intelligenceService.listReports({ operationId: 'operation-123' });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('AND operation_id = $'),
        expect.arrayContaining(['operation-123'])
      );
    });

    it('should apply pagination', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '500' }] })
        .mockResolvedValueOnce({ rows: mockReports });

      await intelligenceService.listReports({ limit: 50, offset: 100 });

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('LIMIT 50 OFFSET 100');
    });

    it('should cap limit at 500', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1000' }] })
        .mockResolvedValueOnce({ rows: mockReports });

      await intelligenceService.listReports({ limit: 1000 });

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('LIMIT 500');
    });

    it('should throw ServiceUnavailableError on database failure', async () => {
      (database.query as jest.Mock).mockRejectedValueOnce(new Error('Connection lost'));

      await expect(intelligenceService.listReports())
        .rejects.toThrow(ServiceUnavailableError);
    });
  });

  describe('correlateReports', () => {
    const reportIds = ['report-1', 'report-2', 'report-3'];

    it('should correlate reports successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{ id: 'report-1' }, { id: 'report-2' }, { id: 'report-3' }],
        })
        .mockResolvedValueOnce({
          rows: [
            { report1_id: 'report-1', report2_id: 'report-2', common_tags: '3' },
            { report1_id: 'report-2', report2_id: 'report-3', common_tags: '1' },
          ],
        });

      const result = await intelligenceService.correlateReports(reportIds);

      expect(result).toHaveProperty('correlations');
      expect(result).toHaveProperty('summary');
      expect(result.summary.totalCorrelations).toBe(2);
      expect(result.summary.strongCorrelations).toBe(1); // Only one with >= 3 common tags
    });

    it('should throw BadRequestError for less than 2 reports', async () => {
      await expect(intelligenceService.correlateReports(['report-1']))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for empty array', async () => {
      await expect(intelligenceService.correlateReports([]))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for more than 50 reports', async () => {
      const tooManyIds = Array(51).fill('report').map((r, i) => `${r}-${i}`);

      await expect(intelligenceService.correlateReports(tooManyIds))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when some reports not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ id: 'report-1' }], // Only one found
      });

      await expect(intelligenceService.correlateReports(reportIds))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{ id: 'report-1' }, { id: 'report-2' }, { id: 'report-3' }],
        })
        .mockRejectedValueOnce(new Error('Correlation failed'));

      await expect(intelligenceService.correlateReports(reportIds))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('scoreConfidence', () => {
    it('should return correct score for VERIFIED confidence', async () => {
      const verifiedReport = { ...mockReport, confidence: ConfidenceLevel.VERIFIED };
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [verifiedReport] });

      const result = await intelligenceService.scoreConfidence('report-123');

      expect(result.score).toBe(1.0);
      expect(result.level).toBe(ConfidenceLevel.VERIFIED);
      expect(result.description).toContain('Verified');
    });

    it('should return correct score for HIGH confidence', async () => {
      const highReport = { ...mockReport, confidence: ConfidenceLevel.HIGH };
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [highReport] });

      const result = await intelligenceService.scoreConfidence('report-123');

      expect(result.score).toBe(0.8);
      expect(result.level).toBe(ConfidenceLevel.HIGH);
    });

    it('should return correct score for MEDIUM confidence', async () => {
      const mediumReport = { ...mockReport, confidence: ConfidenceLevel.MEDIUM };
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mediumReport] });

      const result = await intelligenceService.scoreConfidence('report-123');

      expect(result.score).toBe(0.6);
      expect(result.level).toBe(ConfidenceLevel.MEDIUM);
    });

    it('should return correct score for LOW confidence', async () => {
      const lowReport = { ...mockReport, confidence: ConfidenceLevel.LOW };
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [lowReport] });

      const result = await intelligenceService.scoreConfidence('report-123');

      expect(result.score).toBe(0.4);
      expect(result.level).toBe(ConfidenceLevel.LOW);
    });

    it('should return correct score for UNCONFIRMED confidence', async () => {
      const unconfirmedReport = { ...mockReport, confidence: ConfidenceLevel.UNCONFIRMED };
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [unconfirmedReport] });

      const result = await intelligenceService.scoreConfidence('report-123');

      expect(result.score).toBe(0.2);
      expect(result.level).toBe(ConfidenceLevel.UNCONFIRMED);
    });

    it('should throw NotFoundError when report not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(intelligenceService.scoreConfidence('non-existent'))
        .rejects.toThrow(NotFoundError);
    });
  });

  describe('updateReport', () => {
    it('should update report successfully', async () => {
      const updatedReport = { ...mockReport, title: 'Updated Title' };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockReport] })
        .mockResolvedValueOnce({ rows: [updatedReport] });

      const result = await intelligenceService.updateReport('report-123', {
        title: 'Updated Title',
      });

      expect(result.title).toBe('Updated Title');
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(intelligenceService.updateReport('', { title: 'New' }))
        .rejects.toThrow(BadRequestError);
    });

    it('should return current report when no valid updates', async () => {
      (database.query as jest.Mock).mockResolvedValue({ rows: [mockReport] });

      const result = await intelligenceService.updateReport('report-123', {
        invalidField: 'value',
      } as any);

      expect(result).toEqual(mockReport);
    });

    it('should update tags correctly', async () => {
      const updatedReport = { ...mockReport, tags: ['new-tag'] };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockReport] })
        .mockResolvedValueOnce({ rows: [updatedReport] });

      await intelligenceService.updateReport('report-123', {
        tags: ['new-tag'],
      });

      const updateCall = (database.query as jest.Mock).mock.calls[1];
      expect(updateCall[1]).toContain(JSON.stringify(['new-tag']));
    });

    it('should throw NotFoundError when report not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(intelligenceService.updateReport('non-existent', { title: 'New' }))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockReport] })
        .mockRejectedValueOnce(new Error('Update failed'));

      await expect(intelligenceService.updateReport('report-123', { title: 'New' }))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('deleteReport', () => {
    it('should delete report successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockReport] })
        .mockResolvedValueOnce({ rows: [] });

      await intelligenceService.deleteReport('report-123');

      expect(database.query).toHaveBeenCalledWith(
        'DELETE FROM intelligence_reports WHERE id = $1',
        ['report-123']
      );
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(intelligenceService.deleteReport(''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when report not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(intelligenceService.deleteReport('non-existent'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockReport] })
        .mockRejectedValueOnce(new Error('Delete failed'));

      await expect(intelligenceService.deleteReport('report-123'))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('INTELLIGENCE_ERROR_CODES', () => {
    it('should have correct error codes', () => {
      expect(INTELLIGENCE_ERROR_CODES.REPORT_NOT_FOUND).toBe('INTEL_REPORT_NOT_FOUND');
      expect(INTELLIGENCE_ERROR_CODES.CREATION_FAILED).toBe('INTEL_CREATION_FAILED');
      expect(INTELLIGENCE_ERROR_CODES.INVALID_DATA).toBe('INTEL_INVALID_DATA');
      expect(INTELLIGENCE_ERROR_CODES.CORRELATION_FAILED).toBe('INTEL_CORRELATION_FAILED');
      expect(INTELLIGENCE_ERROR_CODES.DATABASE_ERROR).toBe('INTEL_DATABASE_ERROR');
      expect(INTELLIGENCE_ERROR_CODES.INSUFFICIENT_REPORTS).toBe('INTEL_INSUFFICIENT_REPORTS');
    });
  });
});
