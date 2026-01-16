/**
 * Operation Service Unit Tests
 * Tests for CRUD operations, validation, and error handling
 */

import { OperationService, OPERATION_ERROR_CODES } from '../src/services/operation.service';

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
  generateId: jest.fn(() => 'test-operation-id-12345'),
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
  ConflictError: class ConflictError extends Error {
    code: string;
    constructor(message: string, code?: string) {
      super(message);
      this.name = 'ConflictError';
      this.code = code || 'CONFLICT';
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
  OperationStatus: {
    PLANNING: 'planning',
    ACTIVE: 'active',
    ON_HOLD: 'on_hold',
    COMPLETED: 'completed',
    ARCHIVED: 'archived',
  },
  OperationPriority: {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
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
  ConflictError,
  ServiceUnavailableError,
  OperationStatus,
  OperationPriority,
  ClearanceLevel,
} from '@apollo/shared';

describe('OperationService', () => {
  let operationService: OperationService;

  const mockOperation = {
    id: 'operation-123',
    name: 'Test Operation',
    codename: 'ALPHA',
    description: 'Test operation description',
    status: OperationStatus.PLANNING,
    priority: OperationPriority.HIGH,
    clearanceLevel: ClearanceLevel.SECRET,
    leadInvestigatorId: 'user-123',
    startDate: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(() => {
    operationService = new OperationService();
    jest.clearAllMocks();
  });

  describe('createOperation', () => {
    const validData = {
      name: 'Test Operation',
      codename: 'ALPHA',
      description: 'Description',
      priority: OperationPriority.HIGH,
      clearanceLevel: ClearanceLevel.SECRET,
      leadInvestigatorId: 'user-123',
      startDate: new Date(),
    };

    it('should create operation successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // Check duplicate
        .mockResolvedValueOnce({ rows: [mockOperation] }); // Insert

      const result = await operationService.createOperation(validData);

      expect(result).toHaveProperty('id');
      expect(result.name).toBe(validData.name);
      expect(result.codename).toBe(validData.codename);
    });

    it('should throw BadRequestError when name is empty', async () => {
      const invalidData = { ...validData, name: '' };

      await expect(operationService.createOperation(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when name is whitespace only', async () => {
      const invalidData = { ...validData, name: '   ' };

      await expect(operationService.createOperation(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when codename is empty', async () => {
      const invalidData = { ...validData, codename: '' };

      await expect(operationService.createOperation(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when leadInvestigatorId is missing', async () => {
      const invalidData = { ...validData, leadInvestigatorId: '' };

      await expect(operationService.createOperation(invalidData))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw ConflictError when codename already exists', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ id: 'existing-operation' }],
      });

      await expect(operationService.createOperation(validData))
        .rejects.toThrow(ConflictError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] })
        .mockRejectedValueOnce(new Error('Database error'));

      await expect(operationService.createOperation(validData))
        .rejects.toThrow(InternalServerError);
    });

    it('should trim name and codename', async () => {
      const dataWithWhitespace = {
        ...validData,
        name: '  Trimmed Name  ',
        codename: '  TRIMMED  ',
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.createOperation(dataWithWhitespace);

      expect(database.query).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining(['Trimmed Name', 'TRIMMED'])
      );
    });
  });

  describe('getOperationById', () => {
    it('should return operation when found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [mockOperation],
      });

      const result = await operationService.getOperationById('operation-123');

      expect(result).toEqual(mockOperation);
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(operationService.getOperationById(''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when operation not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(operationService.getOperationById('non-existent'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw ServiceUnavailableError on database failure', async () => {
      (database.query as jest.Mock).mockRejectedValueOnce(new Error('Connection failed'));

      await expect(operationService.getOperationById('operation-123'))
        .rejects.toThrow(ServiceUnavailableError);
    });
  });

  describe('updateOperation', () => {
    it('should update operation successfully', async () => {
      const updatedOperation = { ...mockOperation, name: 'Updated Name' };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] }) // getOperationById
        .mockResolvedValueOnce({ rows: [updatedOperation] }); // Update

      const result = await operationService.updateOperation('operation-123', {
        name: 'Updated Name',
      });

      expect(result.name).toBe('Updated Name');
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(operationService.updateOperation('', { name: 'New Name' }))
        .rejects.toThrow(BadRequestError);
    });

    it('should return current operation when no valid updates provided', async () => {
      (database.query as jest.Mock).mockResolvedValue({ rows: [mockOperation] });

      const result = await operationService.updateOperation('operation-123', {
        invalidField: 'value', // Not in allowed fields
      } as any);

      expect(result).toEqual(mockOperation);
    });

    it('should only update allowed fields', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.updateOperation('operation-123', {
        name: 'New Name',
        id: 'hacked-id', // Should be ignored
        createdAt: new Date(), // Should be ignored
      } as any);

      // Verify only 'name' was in the update query
      const updateCall = (database.query as jest.Mock).mock.calls[1];
      expect(updateCall[0]).toContain('name');
      expect(updateCall[0]).not.toContain('id =');
    });

    it('should convert camelCase to snake_case for database', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.updateOperation('operation-123', {
        clearanceLevel: ClearanceLevel.TOP_SECRET,
      });

      const updateCall = (database.query as jest.Mock).mock.calls[1];
      expect(updateCall[0]).toContain('clearance_level');
    });

    it('should throw NotFoundError when operation does not exist', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        operationService.updateOperation('non-existent', { name: 'New Name' })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure during update', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockRejectedValueOnce(new Error('Update failed'));

      await expect(
        operationService.updateOperation('operation-123', { name: 'New Name' })
      ).rejects.toThrow(InternalServerError);
    });
  });

  describe('deleteOperation', () => {
    it('should delete operation successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] }) // getOperationById
        .mockResolvedValueOnce({ rowCount: 1 }); // Delete

      await operationService.deleteOperation('operation-123');

      expect(database.query).toHaveBeenCalledWith(
        'DELETE FROM operations WHERE id = $1',
        ['operation-123']
      );
    });

    it('should throw BadRequestError when id is empty', async () => {
      await expect(operationService.deleteOperation(''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when operation not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(operationService.deleteOperation('non-existent'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw NotFoundError when delete affects no rows', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockResolvedValueOnce({ rowCount: 0 });

      await expect(operationService.deleteOperation('operation-123'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockRejectedValueOnce(new Error('Delete failed'));

      await expect(operationService.deleteOperation('operation-123'))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('listOperations', () => {
    const mockOperations = [mockOperation, { ...mockOperation, id: 'operation-456' }];

    it('should list operations without filters', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '2' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      const result = await operationService.listOperations();

      expect(result.operations).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should filter by status', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.listOperations({ status: OperationStatus.PLANNING });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('AND status = $1'),
        expect.arrayContaining([OperationStatus.PLANNING])
      );
    });

    it('should filter by priority', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.listOperations({ priority: OperationPriority.CRITICAL });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('AND priority = $'),
        expect.arrayContaining([OperationPriority.CRITICAL])
      );
    });

    it('should filter by both status and priority', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: [mockOperation] });

      await operationService.listOperations({
        status: OperationStatus.ACTIVE,
        priority: OperationPriority.HIGH,
      });

      const countQuery = (database.query as jest.Mock).mock.calls[0][0];
      expect(countQuery).toContain('AND status = $1');
      expect(countQuery).toContain('AND priority = $2');
    });

    it('should apply pagination with limit', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '100' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      await operationService.listOperations({ limit: 10 });

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('LIMIT 10');
    });

    it('should cap limit at 100', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '500' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      await operationService.listOperations({ limit: 200 });

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('LIMIT 100');
    });

    it('should apply offset', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '100' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      await operationService.listOperations({ offset: 20 });

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('OFFSET 20');
    });

    it('should use default limit and offset', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '10' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      await operationService.listOperations();

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('LIMIT 50');
      expect(listQuery).toContain('OFFSET 0');
    });

    it('should order by created_at DESC', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '10' }] })
        .mockResolvedValueOnce({ rows: mockOperations });

      await operationService.listOperations();

      const listQuery = (database.query as jest.Mock).mock.calls[1][0];
      expect(listQuery).toContain('ORDER BY created_at DESC');
    });

    it('should throw ServiceUnavailableError on database failure', async () => {
      (database.query as jest.Mock).mockRejectedValueOnce(new Error('Connection lost'));

      await expect(operationService.listOperations())
        .rejects.toThrow(ServiceUnavailableError);
    });
  });

  describe('assignTeamMember', () => {
    it('should assign team member successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] }) // getOperationById
        .mockResolvedValueOnce({ rows: [] }); // Insert

      await operationService.assignTeamMember('operation-123', 'user-456');

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO operation_team_members'),
        ['operation-123', 'user-456']
      );
    });

    it('should throw BadRequestError when operationId is empty', async () => {
      await expect(operationService.assignTeamMember('', 'user-123'))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when userId is empty', async () => {
      await expect(operationService.assignTeamMember('operation-123', ''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when operation not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(operationService.assignTeamMember('non-existent', 'user-123'))
        .rejects.toThrow(NotFoundError);
    });

    it('should handle duplicate assignment gracefully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockResolvedValueOnce({ rows: [] }); // ON CONFLICT DO NOTHING

      await operationService.assignTeamMember('operation-123', 'user-123');

      // Should not throw
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockRejectedValueOnce(new Error('Insert failed'));

      await expect(operationService.assignTeamMember('operation-123', 'user-456'))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('removeTeamMember', () => {
    it('should remove team member successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] }) // getOperationById
        .mockResolvedValueOnce({ rows: [] }); // Delete

      await operationService.removeTeamMember('operation-123', 'user-456');

      expect(database.query).toHaveBeenCalledWith(
        'DELETE FROM operation_team_members WHERE operation_id = $1 AND user_id = $2',
        ['operation-123', 'user-456']
      );
    });

    it('should throw BadRequestError when operationId is empty', async () => {
      await expect(operationService.removeTeamMember('', 'user-123'))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when userId is empty', async () => {
      await expect(operationService.removeTeamMember('operation-123', ''))
        .rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError when operation not found', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(operationService.removeTeamMember('non-existent', 'user-123'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw InternalServerError on database failure', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [mockOperation] })
        .mockRejectedValueOnce(new Error('Delete failed'));

      await expect(operationService.removeTeamMember('operation-123', 'user-456'))
        .rejects.toThrow(InternalServerError);
    });
  });

  describe('OPERATION_ERROR_CODES', () => {
    it('should have correct error codes', () => {
      expect(OPERATION_ERROR_CODES.NOT_FOUND).toBe('OPERATION_NOT_FOUND');
      expect(OPERATION_ERROR_CODES.CREATION_FAILED).toBe('OPERATION_CREATION_FAILED');
      expect(OPERATION_ERROR_CODES.UPDATE_FAILED).toBe('OPERATION_UPDATE_FAILED');
      expect(OPERATION_ERROR_CODES.DELETE_FAILED).toBe('OPERATION_DELETE_FAILED');
      expect(OPERATION_ERROR_CODES.INVALID_DATA).toBe('OPERATION_INVALID_DATA');
      expect(OPERATION_ERROR_CODES.DUPLICATE_CODENAME).toBe('OPERATION_DUPLICATE_CODENAME');
      expect(OPERATION_ERROR_CODES.DATABASE_ERROR).toBe('OPERATION_DATABASE_ERROR');
      expect(OPERATION_ERROR_CODES.TEAM_ASSIGNMENT_FAILED).toBe('OPERATION_TEAM_ASSIGNMENT_FAILED');
    });
  });
});
