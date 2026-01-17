import { database, logger, generateId, NotFoundError, BadRequestError, InternalServerError, ServiceUnavailableError } from '@apollo/shared';

// Error codes for field report service
export const FIELD_REPORT_ERROR_CODES = {
  NOT_FOUND: 'FIELD_REPORT_NOT_FOUND',
  CREATION_FAILED: 'FIELD_REPORT_CREATION_FAILED',
  UPDATE_FAILED: 'FIELD_REPORT_UPDATE_FAILED',
  DELETE_FAILED: 'FIELD_REPORT_DELETE_FAILED',
  INVALID_DATA: 'FIELD_REPORT_INVALID_DATA',
  DATABASE_ERROR: 'FIELD_REPORT_DATABASE_ERROR',
} as const;

// Field report interface
export interface FieldReport {
  id: string;
  operationId: string;
  title: string;
  content: string;
  createdBy: string;
  status?: string;
  reportType?: string;
  location?: string;
  summary?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Allowed fields for update
const ALLOWED_UPDATE_FIELDS = ['title', 'content', 'summary', 'status', 'report_type', 'location'];

export class FieldReportService {
  async createFieldReport(data: {
    operationId: string;
    title: string;
    content: string;
    createdBy: string;
    summary?: string;
    reportType?: string;
    location?: string;
  }): Promise<FieldReport> {
    // Validate required fields
    if (!data.operationId) {
      throw new BadRequestError('Operation ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }
    if (!data.title || data.title.trim().length === 0) {
      throw new BadRequestError('Report title is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }
    if (!data.content || data.content.trim().length === 0) {
      throw new BadRequestError('Report content is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }
    if (!data.createdBy) {
      throw new BadRequestError('Creator ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify operation exists
      const opCheck = await database.query('SELECT id FROM operations WHERE id = $1', [data.operationId]);
      if (opCheck.rows.length === 0) {
        throw new NotFoundError(`Operation with ID '${data.operationId}' not found`, FIELD_REPORT_ERROR_CODES.INVALID_DATA);
      }

      const id = generateId();
      const result = await database.query<FieldReport>(
        `INSERT INTO field_reports (id, operation_id, title, content, created_by, summary, report_type, location)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [id, data.operationId, data.title.trim(), data.content.trim(), data.createdBy, data.summary || null, data.reportType || null, data.location || null],
      );
      logger.info(`Field report created: ${id} for operation ${data.operationId}`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof BadRequestError || error instanceof NotFoundError) {
        throw error;
      }
      logger.error(`Failed to create field report: ${error.message}`);
      throw new InternalServerError('Failed to create field report', FIELD_REPORT_ERROR_CODES.CREATION_FAILED);
    }
  }

  async getFieldReportById(id: string): Promise<FieldReport> {
    if (!id) {
      throw new BadRequestError('Field report ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }

    try {
      const result = await database.query<FieldReport>('SELECT * FROM field_reports WHERE id = $1', [id]);
      if (result.rows.length === 0) {
        throw new NotFoundError(`Field report with ID '${id}' not found`, FIELD_REPORT_ERROR_CODES.NOT_FOUND);
      }
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to retrieve field report ${id}: ${error.message}`);
      throw new ServiceUnavailableError('Database service unavailable', FIELD_REPORT_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async updateFieldReport(id: string, updates: Partial<FieldReport>): Promise<FieldReport> {
    if (!id) {
      throw new BadRequestError('Field report ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify report exists
      await this.getFieldReportById(id);

      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      // Only allow whitelisted fields for security
      Object.entries(updates).forEach(([key, value]) => {
        const snakeKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
        if (value !== undefined && ALLOWED_UPDATE_FIELDS.includes(snakeKey)) {
          fields.push(`${snakeKey} = $${idx++}`);
          values.push(typeof value === 'string' ? value.trim() : value);
        }
      });

      if (fields.length === 0) {
        return this.getFieldReportById(id);
      }

      values.push(id);
      const result = await database.query<FieldReport>(
        `UPDATE field_reports SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values,
      );

      if (result.rows.length === 0) {
        throw new NotFoundError(`Field report with ID '${id}' not found`, FIELD_REPORT_ERROR_CODES.NOT_FOUND);
      }
      logger.info(`Field report updated: ${id}`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to update field report ${id}: ${error.message}`);
      throw new InternalServerError('Failed to update field report', FIELD_REPORT_ERROR_CODES.UPDATE_FAILED);
    }
  }

  async deleteFieldReport(id: string): Promise<void> {
    if (!id) {
      throw new BadRequestError('Field report ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify report exists
      await this.getFieldReportById(id);

      const result = await database.query('DELETE FROM field_reports WHERE id = $1', [id]);
      if (result.rowCount === 0) {
        throw new NotFoundError(`Field report with ID '${id}' not found`, FIELD_REPORT_ERROR_CODES.NOT_FOUND);
      }
      logger.info(`Field report deleted: ${id}`);
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to delete field report ${id}: ${error.message}`);
      throw new InternalServerError('Failed to delete field report', FIELD_REPORT_ERROR_CODES.DELETE_FAILED);
    }
  }

  async listByOperationId(operationId: string, options?: { limit?: number; offset?: number }): Promise<{ reports: FieldReport[]; total: number }> {
    if (!operationId) {
      throw new BadRequestError('Operation ID is required', FIELD_REPORT_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Get total count
      const countResult = await database.query(
        'SELECT COUNT(*) FROM field_reports WHERE operation_id = $1',
        [operationId]
      );
      const total = parseInt(countResult.rows[0]?.count || '0', 10);

      // Get reports with pagination
      const limit = Math.min(options?.limit || 50, 100);
      const offset = options?.offset || 0;

      const result = await database.query<FieldReport>(
        `SELECT * FROM field_reports WHERE operation_id = $1 ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`,
        [operationId],
      );
      return { reports: result.rows, total };
    } catch (error: any) {
      if (error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to list field reports for operation ${operationId}: ${error.message}`);
      throw new ServiceUnavailableError('Failed to retrieve field reports', FIELD_REPORT_ERROR_CODES.DATABASE_ERROR);
    }
  }
}

export const fieldReportService = new FieldReportService();
