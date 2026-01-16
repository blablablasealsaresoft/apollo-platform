import { database, logger, generateId, NotFoundError, BadRequestError, InternalServerError, ConflictError, ServiceUnavailableError, Operation, OperationStatus, OperationPriority, ClearanceLevel } from '@apollo/shared';

// Error codes for operation service
export const OPERATION_ERROR_CODES = {
  NOT_FOUND: 'OPERATION_NOT_FOUND',
  CREATION_FAILED: 'OPERATION_CREATION_FAILED',
  UPDATE_FAILED: 'OPERATION_UPDATE_FAILED',
  DELETE_FAILED: 'OPERATION_DELETE_FAILED',
  INVALID_DATA: 'OPERATION_INVALID_DATA',
  DUPLICATE_CODENAME: 'OPERATION_DUPLICATE_CODENAME',
  DATABASE_ERROR: 'OPERATION_DATABASE_ERROR',
  TEAM_ASSIGNMENT_FAILED: 'OPERATION_TEAM_ASSIGNMENT_FAILED',
} as const;

// Allowed fields for update to prevent SQL injection
const ALLOWED_UPDATE_FIELDS = ['name', 'codename', 'description', 'status', 'priority', 'clearance_level', 'end_date'];

export class OperationService {
  async createOperation(data: {
    name: string;
    codename: string;
    description: string;
    priority: OperationPriority;
    clearanceLevel: ClearanceLevel;
    leadInvestigatorId: string;
    startDate: Date;
  }): Promise<Operation> {
    // Validate required fields
    if (!data.name || data.name.trim().length === 0) {
      throw new BadRequestError('Operation name is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.codename || data.codename.trim().length === 0) {
      throw new BadRequestError('Operation codename is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }
    if (!data.leadInvestigatorId) {
      throw new BadRequestError('Lead investigator ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Check for duplicate codename
      const existing = await database.query('SELECT id FROM operations WHERE codename = $1', [data.codename]);
      if (existing.rows.length > 0) {
        throw new ConflictError(`Operation with codename '${data.codename}' already exists`, OPERATION_ERROR_CODES.DUPLICATE_CODENAME);
      }

      const id = generateId();
      const result = await database.query<Operation>(
        `INSERT INTO operations (id, name, codename, description, status, priority, clearance_level, lead_investigator_id, start_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [id, data.name.trim(), data.codename.trim(), data.description, OperationStatus.PLANNING, data.priority, data.clearanceLevel, data.leadInvestigatorId, data.startDate],
      );
      logger.info(`Operation created: ${id} (codename: ${data.codename})`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof BadRequestError || error instanceof ConflictError) {
        throw error;
      }
      logger.error(`Failed to create operation: ${error.message}`);
      throw new InternalServerError('Failed to create operation', OPERATION_ERROR_CODES.CREATION_FAILED);
    }
  }

  async getOperationById(id: string): Promise<Operation> {
    if (!id) {
      throw new BadRequestError('Operation ID is required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      const result = await database.query<Operation>('SELECT * FROM operations WHERE id = $1', [id]);
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

  async updateOperation(id: string, updates: Partial<Operation>): Promise<Operation> {
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
      const result = await database.query<Operation>(
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

  async listOperations(filters?: { status?: OperationStatus; priority?: OperationPriority; limit?: number; offset?: number }): Promise<{ operations: Operation[]; total: number }> {
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

      // Get total count
      const countResult = await database.query(countQuery, params);
      const total = parseInt(countResult.rows[0]?.count || '0', 10);

      // Add pagination
      query += ' ORDER BY created_at DESC';
      const limit = Math.min(filters?.limit || 50, 100); // Cap at 100
      const offset = filters?.offset || 0;
      query += ` LIMIT ${limit} OFFSET ${offset}`;

      const result = await database.query<Operation>(query, params);
      return { operations: result.rows, total };
    } catch (error: any) {
      logger.error(`Failed to list operations: ${error.message}`);
      throw new ServiceUnavailableError('Failed to retrieve operations', OPERATION_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async assignTeamMember(operationId: string, userId: string): Promise<void> {
    if (!operationId || !userId) {
      throw new BadRequestError('Operation ID and User ID are required', OPERATION_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify operation exists
      await this.getOperationById(operationId);

      await database.query(
        'INSERT INTO operation_team_members (operation_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [operationId, userId],
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

      await database.query(
        'DELETE FROM operation_team_members WHERE operation_id = $1 AND user_id = $2',
        [operationId, userId],
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
}

export const operationService = new OperationService();
