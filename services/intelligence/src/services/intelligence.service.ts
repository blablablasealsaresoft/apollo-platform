import { database, logger, generateId, IntelligenceReport, IntelligenceSource, ConfidenceLevel, ClearanceLevel } from '@apollo/shared';

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
    const id = generateId();
    const result = await database.query<IntelligenceReport>(
      `INSERT INTO intelligence_reports
       (id, title, summary, content, source, confidence, clearance_level, author_id, operation_id, target_id, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [id, data.title, data.summary, data.content, data.source, data.confidence, data.clearanceLevel,
       data.authorId, data.operationId, data.targetId, JSON.stringify(data.tags)],
    );
    logger.info(`Intelligence report created: ${id}`);
    return result.rows[0]!;
  }

  async getReportById(id: string): Promise<IntelligenceReport> {
    const result = await database.query<IntelligenceReport>('SELECT * FROM intelligence_reports WHERE id = $1', [id]);
    return result.rows[0]!;
  }

  async listReports(filters?: { source?: IntelligenceSource; confidence?: ConfidenceLevel; operationId?: string }): Promise<IntelligenceReport[]> {
    let query = 'SELECT * FROM intelligence_reports WHERE 1=1';
    const params: any[] = [];
    let idx = 1;

    if (filters?.source) {
      query += ` AND source = $${idx++}`;
      params.push(filters.source);
    }
    if (filters?.confidence) {
      query += ` AND confidence = $${idx++}`;
      params.push(filters.confidence);
    }
    if (filters?.operationId) {
      query += ` AND operation_id = $${idx++}`;
      params.push(filters.operationId);
    }

    query += ' ORDER BY created_at DESC LIMIT 100';
    const result = await database.query<IntelligenceReport>(query, params);
    return result.rows;
  }

  async correlateReports(reportIds: string[]): Promise<any> {
    // Simple correlation based on common tags and entities
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
    return result.rows;
  }

  async scoreConfidence(reportId: string): Promise<number> {
    const report = await this.getReportById(reportId);
    const confidenceScores = {
      [ConfidenceLevel.VERIFIED]: 1.0,
      [ConfidenceLevel.HIGH]: 0.8,
      [ConfidenceLevel.MEDIUM]: 0.6,
      [ConfidenceLevel.LOW]: 0.4,
      [ConfidenceLevel.UNCONFIRMED]: 0.2,
    };
    return confidenceScores[report.confidence] || 0.5;
  }
}

export const intelligenceService = new IntelligenceService();
