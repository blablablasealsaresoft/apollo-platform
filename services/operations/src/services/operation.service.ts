import { database, logger, generateId, NotFoundError, BadRequestError, InternalServerError, ConflictError, ServiceUnavailableError } from '@apollo/shared';

// Error codes for operation service
export const OPERATION_ERROR_CODES = {
  NOT_FOUND: 'OPERATION_NOT_FOUND',
  CREATION_FAILED: 'OPERATION_CREATION_FAILED',
  UPDATE_FAILED: 'OPERATION_UPDATE_FAILED',
  DELETE_FAILED: 'OPERATION_DELETE_FAILED',
  INVALID_DATA: 'OPERATION_INVALID_DATA',
  DUPLICATE_OPERATION_NUMBER: 'OPERATION_DUPLICATE_NUMBER',
  DATABASE_ERROR: 'OPERATION_DATABASE_ERROR',
  TEAM_ASSIGNMENT_FAILED: 'OPERATION_TEAM_ASSIGNMENT_FAILED',
} as const;

// Operation types matching database enum
export const OPERATION_TYPES = [
  'surveillance',
  'arrest',
  'search_warrant',
  'undercover',
  'interview',
  'raid',
  'protective',
  'reconnaissance',
  'sting',
  'other',
] as const;
export type OperationType = typeof OPERATION_TYPES[number];

// Operation status values
export const OPERATION_STATUS = ['planning', 'approved', 'in_progress', 'completed', 'cancelled'] as const;
export type OperationStatusType = typeof OPERATION_STATUS[number];

// Operation priority values
export const OPERATION_PRIORITY = ['low', 'medium', 'high', 'critical'] as const;
export type OperationPriorityType = typeof OPERATION_PRIORITY[number];

// Operation interface matching database schema
export interface OperationRecord {
  id: string;
  investigation_id: string;
  target_id?: string;
  operation_number?: string;
  operation_name: string;
  operation_type: OperationType;
  status: OperationStatusType;
  priority: OperationPriorityType;
  objective: string;
  strategy?: string;
  resources_required?: string;
  risk_assessment?: string;
  legal_authorization?: string;
  warrant_numbers?: string[];
  planned_date?: Date;
  scheduled_start?: Date;
  scheduled_end?: Date;
  actual_start?: Date;
  actual_end?: Date;
  operation_lead?: string;
  team_members?: string[];
  external_agencies?: string[];
  operation_location?: string;
  outcome?: string;
  result_summary?: string;
  classification_level?: string;
  metadata?: Record<string, any>;
  created_at: Date;
  updated_at: Date;
  created_by: string;
}

// Allowed fields for update to prevent SQL injection
const ALLOWED_UPDATE_FIELDS = [
  'operation_name', 'operation_type', 'status', 'priority', 'objective',
  'strategy', 'resources_required', 'risk_assessment', 'legal_authorization',
  'planned_date', 'scheduled_start', 'scheduled_end', 'actual_start', 'actual_end',
  'operation_lead', 'operation_location', 'outcome', 'result_summary',
  'classification_level', 'after_action_report', 'lessons_learned',
  'follow_up_required', 'follow_up_notes'
];

export class OperationService {
  async createOperation(data: {
    investigationId: string;
    operationName: string;
    operationType: OperationType;
    objective: string;
    createdBy: string;
    targetId?: string;
    operationNumber?: string;
    priority?: OperationPriorityType;
    strategy?: string;
    plannedDate?: Date;
    operationLead?: string;
    operationLocation?: string;
    classificationLevel?: string;
  }): Promise<OperationRecord> {
    // Validate required fields
    if (!data.investigationId) {
      throw new BadRequestError('Investigation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.operationName || data.operationName.trim().length === 0) {
      throw new BadRequestError('Operation name is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.operationType || !OPERATION_TYPES.includes(data.operationType)) {
      throw new BadRequestError(`Invalid operation type. Must be one of: ${OPERATION_TYPES.join(', ')}`, OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.objective || data.objective.trim().length === 0) {
      throw new BadRequestError('Operation objective is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.createdBy) {
      throw new BadRequestError('Creator ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Check for duplicate operation number if provided
      if (data.operationNumber) {
        const existing = await database.query('SELECT id FROM operations WHERE operation_number = $1', [data.operationNumber]);
        if (existing.rows.length > 0) {
          throw new ConflictError(`Operation with number '${data.operationNumber}' already exists`, OPERATION_ERROR_CODES.DUPLICATE_OPERATION_NUMBER);
        }
      }

      const id = generateId();
      const result = await database.query<OperationRecord>(
        `INSERT INTO operations (
          id, investigation_id, target_id, operation_number, operation_name,
          operation_type, status, priority, objective, strategy,
          planned_date, operation_lead, operation_location, classification_level, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         RETURNING *`,
        [
          id,
          data.investigationId,
          data.targetId || null,
          data.operationNumber || null,
          data.operationName.trim(),
          data.operationType,
          'planning',
          data.priority || 'medium',
          data.objective.trim(),
          data.strategy || null,
          data.plannedDate || null,
          data.operationLead || null,
          data.operationLocation || null,
          data.classificationLevel || 'SECRET',
          data.createdBy
        ],
      );
      logger.info(`Operation created: ${id} (name: ${data.operationName})`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof BadRequestError || error instanceof ConflictError) {
        throw error;
      }
      logger.error(`Failed to create operation: ${error.message}`);
      throw new InternalServerError('Failed to create operation', OPERATION_ERROR_CODES.CREATION_FAILED);
    }
  }

  async getOperationById(id: string): Promise<OperationRecord> {
    if (!id) {
      throw new BadRequestError('Operation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      const result = await database.query<OperationRecord>('SELECT * FROM operations WHERE id = $1', [id]);
      if (result.rows.length === 0) {
        throw new NotFoundError(`Operation with ID '${id}' not found`, OPERATION_ERROR_CODES.NOT_FOUND);
      }
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to retrieve operation ${id}: ${error.message}`);
      throw new ServiceUnavailableError('Database service unavailable', OPERATION_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async updateOperation(id: string, updates: Partial<OperationRecord>): Promise<OperationRecord> {
    if (!id) {
      throw new BadRequestError('Operation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // First verify operation exists
      await this.getOperationById(id);

      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      // Only allow whitelisted fields for security
      Object.entries(updates).forEach(([key, value]) => {
        const snakeKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
        if (value !== undefined && ALLOWED_UPDATE_FIELDS.includes(snakeKey)) {
          fields.push(`${snakeKey} = $${idx++}`);
          values.push(value);
        }
      });

      if (fields.length === 0) {
        return this.getOperationById(id);
      }

      values.push(id);
      const result = await database.query<OperationRecord>(
        `UPDATE operations SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values,
      );

      if (result.rows.length === 0) {
        throw new NotFoundError(`Operation with ID '${id}' not found`, OPERATION_ERROR_CODES.NOT_FOUND);
      }
      logger.info(`Operation updated: ${id}`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to update operation ${id}: ${error.message}`);
      throw new InternalServerError('Failed to update operation', OPERATION_ERROR_CODES.UPDATE_FAILED);
    }
  }

  async deleteOperation(id: string): Promise<void> {
    if (!id) {
      throw new BadRequestError('Operation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // First verify operation exists
      await this.getOperationById(id);

      const result = await database.query('DELETE FROM operations WHERE id = $1', [id]);
      if (result.rowCount === 0) {
        throw new NotFoundError(`Operation with ID '${id}' not found`, OPERATION_ERROR_CODES.NOT_FOUND);
      }
      logger.info(`Operation deleted: ${id}`);
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to delete operation ${id}: ${error.message}`);
      throw new InternalServerError('Failed to delete operation', OPERATION_ERROR_CODES.DELETE_FAILED);
    }
  }

  async listOperations(filters?: {
    status?: OperationStatusType;
    priority?: OperationPriorityType;
    investigationId?: string;
    operationType?: OperationType;
    limit?: number;
    offset?: number
  }): Promise<{ operations: OperationRecord[]; total: number }> {
    try {
      let countQuery = 'SELECT COUNT(*) FROM operations WHERE 1=1';
      let query = 'SELECT * FROM operations WHERE 1=1';
      const params: any[] = [];
      let paramIdx = 1;

      if (filters?.status) {
        const statusFilter = ` AND status = $${paramIdx++}`;
        countQuery += statusFilter;
        query += statusFilter;
        params.push(filters.status);
      }
      if (filters?.priority) {
        const priorityFilter = ` AND priority = $${paramIdx++}`;
        countQuery += priorityFilter;
        query += priorityFilter;
        params.push(filters.priority);
      }
      if (filters?.investigationId) {
        const investigationFilter = ` AND investigation_id = $${paramIdx++}`;
        countQuery += investigationFilter;
        query += investigationFilter;
        params.push(filters.investigationId);
      }
      if (filters?.operationType) {
        const typeFilter = ` AND operation_type = $${paramIdx++}`;
        countQuery += typeFilter;
        query += typeFilter;
        params.push(filters.operationType);
      }

      // Get total count
      const countResult = await database.query(countQuery, params);
      const total = parseInt(countResult.rows[0]?.count || '0', 10);

      // Add pagination
      query += ' ORDER BY created_at DESC';
      const limit = Math.min(filters?.limit || 50, 100); // Cap at 100
      const offset = filters?.offset || 0;
      query += ` LIMIT ${limit} OFFSET ${offset}`;

      const result = await database.query<OperationRecord>(query, params);
      return { operations: result.rows, total };
    } catch (error: any) {
      logger.error(`Failed to list operations: ${error.message}`);
      throw new ServiceUnavailableError('Failed to retrieve operations', OPERATION_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async getOperationsByInvestigation(investigationId: string, options?: { limit?: number; offset?: number }): Promise<{ operations: OperationRecord[]; total: number }> {
    if (!investigationId) {
      throw new BadRequestError('Investigation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    return this.listOperations({ investigationId, ...options });
  }

  async updateOperationStatus(id: string, status: OperationStatusType, updatedBy: string): Promise<OperationRecord> {
    if (!OPERATION_STATUS.includes(status)) {
      throw new BadRequestError(`Invalid status. Must be one of: ${OPERATION_STATUS.join(', ')}`, OPERATION_ERROR_CODES.INVALID_DATA);
    }

    // Handle actual_start and actual_end based on status
    const updates: Partial<OperationRecord> = { status };
    if (status === 'in_progress') {
      updates.actual_start = new Date();
    } else if (status === 'completed' || status === 'cancelled') {
      updates.actual_end = new Date();
    }

    return this.updateOperation(id, updates);
  }

  async assignTeamMember(operationId: string, userId: string): Promise<void> {
    if (!operationId || !userId) {
      throw new BadRequestError('Operation ID and User ID are required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify operation exists
      const operation = await this.getOperationById(operationId);

      // Add user to team_members array
      await database.query(
        `UPDATE operations
         SET team_members = array_append(COALESCE(team_members, ARRAY[]::UUID[]), $1::UUID),
             updated_at = NOW()
         WHERE id = $2 AND NOT ($1::UUID = ANY(COALESCE(team_members, ARRAY[]::UUID[])))`,
        [userId, operationId],
      );
      logger.info(`Team member ${userId} assigned to operation ${operationId}`);
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to assign team member: ${error.message}`);
      throw new InternalServerError('Failed to assign team member', OPERATION_ERROR_CODES.TEAM_ASSIGNMENT_FAILED);
    }
  }

  async removeTeamMember(operationId: string, userId: string): Promise<void> {
    if (!operationId || !userId) {
      throw new BadRequestError('Operation ID and User ID are required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify operation exists
      await this.getOperationById(operationId);

      // Remove user from team_members array
      await database.query(
        `UPDATE operations
         SET team_members = array_remove(COALESCE(team_members, ARRAY[]::UUID[]), $1::UUID),
             updated_at = NOW()
         WHERE id = $2`,
        [userId, operationId],
      );
      logger.info(`Team member ${userId} removed from operation ${operationId}`);
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to remove team member: ${error.message}`);
      throw new InternalServerError('Failed to remove team member', OPERATION_ERROR_CODES.TEAM_ASSIGNMENT_FAILED);
    }
  }

  async getTeamMembers(operationId: string): Promise<string[]> {
    if (!operationId) {
      throw new BadRequestError('Operation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      const operation = await this.getOperationById(operationId);
      return operation.team_members || [];
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to get team members: ${error.message}`);
      throw new ServiceUnavailableError('Failed to retrieve team members', OPERATION_ERROR_CODES.DATABASE_ERROR);
    }
  }
}

export const operationService = new OperationService();
