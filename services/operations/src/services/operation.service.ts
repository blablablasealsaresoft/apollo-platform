import { database, logger, generateId, NotFoundError, Operation, OperationStatus, OperationPriority, ClearanceLevel } from '@apollo/shared';

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
    const id = generateId();
    const result = await database.query<Operation>(
      `INSERT INTO operations (id, name, codename, description, status, priority, clearance_level, lead_investigator_id, start_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [id, data.name, data.codename, data.description, OperationStatus.PLANNING, data.priority, data.clearanceLevel, data.leadInvestigatorId, data.startDate],
    );
    logger.info(`Operation created: ${id}`);
    return result.rows[0]!;
  }

  async getOperationById(id: string): Promise<Operation> {
    const result = await database.query<Operation>('SELECT * FROM operations WHERE id = $1', [id]);
    if (result.rows.length === 0) throw new NotFoundError('Operation not found');
    return result.rows[0]!;
  }

  async updateOperation(id: string, updates: Partial<Operation>): Promise<Operation> {
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    Object.entries(updates).forEach(([key, value]) => {
      if (value !== undefined) {
        fields.push(`${key} = $${idx++}`);
        values.push(value);
      }
    });

    if (fields.length === 0) return this.getOperationById(id);

    values.push(id);
    const result = await database.query<Operation>(
      `UPDATE operations SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
      values,
    );

    if (result.rows.length === 0) throw new NotFoundError('Operation not found');
    logger.info(`Operation updated: ${id}`);
    return result.rows[0]!;
  }

  async deleteOperation(id: string): Promise<void> {
    const result = await database.query('DELETE FROM operations WHERE id = $1', [id]);
    if (result.rowCount === 0) throw new NotFoundError('Operation not found');
    logger.info(`Operation deleted: ${id}`);
  }

  async listOperations(filters?: { status?: OperationStatus; priority?: OperationPriority }): Promise<Operation[]> {
    let query = 'SELECT * FROM operations WHERE 1=1';
    const params: any[] = [];
    let paramIdx = 1;

    if (filters?.status) {
      query += ` AND status = $${paramIdx++}`;
      params.push(filters.status);
    }
    if (filters?.priority) {
      query += ` AND priority = $${paramIdx++}`;
      params.push(filters.priority);
    }

    query += ' ORDER BY created_at DESC';
    const result = await database.query<Operation>(query, params);
    return result.rows;
  }

  async assignTeamMember(operationId: string, userId: string): Promise<void> {
    await database.query(
      'INSERT INTO operation_team_members (operation_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [operationId, userId],
    );
    logger.info(`Team member ${userId} assigned to operation ${operationId}`);
  }

  async removeTeamMember(operationId: string, userId: string): Promise<void> {
    await database.query(
      'DELETE FROM operation_team_members WHERE operation_id = $1 AND user_id = $2',
      [operationId, userId],
    );
    logger.info(`Team member ${userId} removed from operation ${operationId}`);
  }
}

export const operationService = new OperationService();
