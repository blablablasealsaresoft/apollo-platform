import { database, logger, generateId, NotFoundError, BadRequestError, InternalServerError, ServiceUnavailableError, IntelligenceReport, IntelligenceSource, ConfidenceLevel, ClearanceLevel } from '@apollo/shared';

// Error codes for intelligence service
export const INTELLIGENCE_ERROR_CODES = {
  REPORT_NOT_FOUND: 'INTEL_REPORT_NOT_FOUND',
  CREATION_FAILED: 'INTEL_CREATION_FAILED',
  INVALID_DATA: 'INTEL_INVALID_DATA',
  CORRELATION_FAILED: 'INTEL_CORRELATION_FAILED',
  DATABASE_ERROR: 'INTEL_DATABASE_ERROR',
  INSUFFICIENT_REPORTS: 'INTEL_INSUFFICIENT_REPORTS',
} as const;

export class IntelligenceService {
  async createReport(data: {
    title: string;
    summary: string;
    content: string;
    source: IntelligenceSource;
    confidence: ConfidenceLevel;
    clearanceLevel: ClearanceLevel;
    authorId: string;
    operationId?: string;
    targetId?: string;
    tags: string[];
  }): Promise<IntelligenceReport> {
    // Validate required fields
    if (!data.title || data.title.trim().length === 0) {
      throw new BadRequestError('Report title is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }
    if (!data.summary || data.summary.trim().length === 0) {
      throw new BadRequestError('Report summary is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }
    if (!data.content || data.content.trim().length === 0) {
      throw new BadRequestError('Report content is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }
    if (!data.authorId) {
      throw new BadRequestError('Author ID is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }
    if (!Object.values(IntelligenceSource).includes(data.source)) {
      throw new BadRequestError(`Invalid intelligence source: ${data.source}`, INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }
    if (!Object.values(ConfidenceLevel).includes(data.confidence)) {
      throw new BadRequestError(`Invalid confidence level: ${data.confidence}`, INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }

    try {
      const id = generateId();
      const sanitizedTags = Array.isArray(data.tags) ? data.tags.filter(tag => typeof tag === 'string') : [];

      const result = await database.query<IntelligenceReport>(
        `INSERT INTO intelligence_reports
         (id, title, summary, content, source, confidence, clearance_level, author_id, operation_id, target_id, tags)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *`,
        [id, data.title.trim(), data.summary.trim(), data.content, data.source, data.confidence, data.clearanceLevel,
         data.authorId, data.operationId || null, data.targetId || null, JSON.stringify(sanitizedTags)],
      );
      logger.info(`Intelligence report created: ${id} (title: ${data.title})`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to create intelligence report: ${error.message}`);
      throw new InternalServerError('Failed to create intelligence report', INTELLIGENCE_ERROR_CODES.CREATION_FAILED);
    }
  }

  async getReportById(id: string): Promise<IntelligenceReport> {
    if (!id) {
      throw new BadRequestError('Report ID is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }

    try {
      const result = await database.query<IntelligenceReport>('SELECT * FROM intelligence_reports WHERE id = $1', [id]);
      if (result.rows.length === 0) {
        throw new NotFoundError(`Intelligence report with ID '${id}' not found`, INTELLIGENCE_ERROR_CODES.REPORT_NOT_FOUND);
      }
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to retrieve intelligence report ${id}: ${error.message}`);
      throw new ServiceUnavailableError('Database service unavailable', INTELLIGENCE_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async listReports(filters?: {
    source?: IntelligenceSource;
    confidence?: ConfidenceLevel;
    operationId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ reports: IntelligenceReport[]; total: number }> {
    try {
      let countQuery = 'SELECT COUNT(*) FROM intelligence_reports WHERE 1=1';
      let query = 'SELECT * FROM intelligence_reports WHERE 1=1';
      const params: any[] = [];
      let idx = 1;

      if (filters?.source) {
        if (!Object.values(IntelligenceSource).includes(filters.source)) {
          throw new BadRequestError(`Invalid intelligence source filter: ${filters.source}`, INTELLIGENCE_ERROR_CODES.INVALID_DATA);
        }
        const sourceFilter = ` AND source = $${idx++}`;
        countQuery += sourceFilter;
        query += sourceFilter;
        params.push(filters.source);
      }
      if (filters?.confidence) {
        if (!Object.values(ConfidenceLevel).includes(filters.confidence)) {
          throw new BadRequestError(`Invalid confidence level filter: ${filters.confidence}`, INTELLIGENCE_ERROR_CODES.INVALID_DATA);
        }
        const confidenceFilter = ` AND confidence = $${idx++}`;
        countQuery += confidenceFilter;
        query += confidenceFilter;
        params.push(filters.confidence);
      }
      if (filters?.operationId) {
        const operationFilter = ` AND operation_id = $${idx++}`;
        countQuery += operationFilter;
        query += operationFilter;
        params.push(filters.operationId);
      }

      // Get total count
      const countResult = await database.query(countQuery, params);
      const total = parseInt(countResult.rows[0]?.count || '0', 10);

      // Add pagination
      query += ' ORDER BY created_at DESC';
      const limit = Math.min(filters?.limit || 100, 500); // Cap at 500
      const offset = filters?.offset || 0;
      query += ` LIMIT ${limit} OFFSET ${offset}`;

      const result = await database.query<IntelligenceReport>(query, params);
      return { reports: result.rows, total };
    } catch (error: any) {
      if (error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to list intelligence reports: ${error.message}`);
      throw new ServiceUnavailableError('Failed to retrieve intelligence reports', INTELLIGENCE_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async correlateReports(reportIds: string[]): Promise<{ correlations: any[]; summary: { totalCorrelations: number; strongCorrelations: number } }> {
    if (!Array.isArray(reportIds) || reportIds.length < 2) {
      throw new BadRequestError('At least two report IDs are required for correlation', INTELLIGENCE_ERROR_CODES.INSUFFICIENT_REPORTS);
    }

    // Limit the number of reports for correlation to prevent expensive queries
    if (reportIds.length > 50) {
      throw new BadRequestError('Maximum 50 reports can be correlated at once', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify all reports exist
      const existingReports = await database.query(
        'SELECT id FROM intelligence_reports WHERE id = ANY($1)',
        [reportIds]
      );

      if (existingReports.rows.length !== reportIds.length) {
        const foundIds = new Set(existingReports.rows.map((r: any) => r.id));
        const missingIds = reportIds.filter(id => !foundIds.has(id));
        throw new NotFoundError(`Reports not found: ${missingIds.join(', ')}`, INTELLIGENCE_ERROR_CODES.REPORT_NOT_FOUND);
      }

      const result = await database.query(
        `SELECT ir1.id as report1_id, ir2.id as report2_id,
                COUNT(*) as common_tags
         FROM intelligence_reports ir1
         JOIN intelligence_reports ir2 ON ir1.id < ir2.id
         WHERE ir1.id = ANY($1) AND ir2.id = ANY($1)
           AND EXISTS (
             SELECT 1 FROM jsonb_array_elements_text(ir1.tags) t1
             WHERE t1 IN (SELECT jsonb_array_elements_text(ir2.tags))
           )
         GROUP BY ir1.id, ir2.id
         HAVING COUNT(*) > 0
         ORDER BY COUNT(*) DESC`,
        [reportIds],
      );

      const correlations = result.rows;
      const strongCorrelations = correlations.filter((c: any) => parseInt(c.common_tags) >= 3).length;

      return {
        correlations,
        summary: {
          totalCorrelations: correlations.length,
          strongCorrelations,
        }
      };
    } catch (error: any) {
      if (error instanceof BadRequestError || error instanceof NotFoundError) {
        throw error;
      }
      logger.error(`Failed to correlate reports: ${error.message}`);
      throw new InternalServerError('Failed to correlate reports', INTELLIGENCE_ERROR_CODES.CORRELATION_FAILED);
    }
  }

  async scoreConfidence(reportId: string): Promise<{ score: number; level: ConfidenceLevel; description: string }> {
    const report = await this.getReportById(reportId);

    const confidenceData: Record<ConfidenceLevel, { score: number; description: string }> = {
      [ConfidenceLevel.VERIFIED]: { score: 1.0, description: 'Verified through multiple independent sources' },
      [ConfidenceLevel.HIGH]: { score: 0.8, description: 'High confidence based on reliable sources' },
      [ConfidenceLevel.MEDIUM]: { score: 0.6, description: 'Moderate confidence with some corroboration' },
      [ConfidenceLevel.LOW]: { score: 0.4, description: 'Low confidence, limited corroboration' },
      [ConfidenceLevel.UNCONFIRMED]: { score: 0.2, description: 'Unconfirmed, single source or unverified' },
    };

    const data = confidenceData[report.confidence] || { score: 0.5, description: 'Unknown confidence level' };

    return {
      score: data.score,
      level: report.confidence,
      description: data.description,
    };
  }

  async updateReport(id: string, updates: Partial<Pick<IntelligenceReport, 'title' | 'summary' | 'content' | 'confidence' | 'tags'>>): Promise<IntelligenceReport> {
    if (!id) {
      throw new BadRequestError('Report ID is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify report exists
      await this.getReportById(id);

      const allowedFields = ['title', 'summary', 'content', 'confidence', 'tags'];
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      Object.entries(updates).forEach(([key, value]) => {
        if (value !== undefined && allowedFields.includes(key)) {
          if (key === 'tags') {
            fields.push(`${key} = $${idx++}`);
            values.push(JSON.stringify(Array.isArray(value) ? value : []));
          } else {
            fields.push(`${key} = $${idx++}`);
            values.push(value);
          }
        }
      });

      if (fields.length === 0) {
        return this.getReportById(id);
      }

      values.push(id);
      const result = await database.query<IntelligenceReport>(
        `UPDATE intelligence_reports SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values,
      );

      logger.info(`Intelligence report updated: ${id}`);
      return result.rows[0]!;
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to update intelligence report ${id}: ${error.message}`);
      throw new InternalServerError('Failed to update intelligence report', INTELLIGENCE_ERROR_CODES.DATABASE_ERROR);
    }
  }

  async deleteReport(id: string): Promise<void> {
    if (!id) {
      throw new BadRequestError('Report ID is required', INTELLIGENCE_ERROR_CODES.INVALID_DATA);
    }

    try {
      // Verify report exists
      await this.getReportById(id);

      await database.query('DELETE FROM intelligence_reports WHERE id = $1', [id]);
      logger.info(`Intelligence report deleted: ${id}`);
    } catch (error: any) {
      if (error instanceof NotFoundError || error instanceof BadRequestError) {
        throw error;
      }
      logger.error(`Failed to delete intelligence report ${id}: ${error.message}`);
      throw new InternalServerError('Failed to delete intelligence report', INTELLIGENCE_ERROR_CODES.DATABASE_ERROR);
    }
  }
}

export const intelligenceService = new IntelligenceService();
