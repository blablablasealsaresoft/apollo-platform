import { database, logger } from '@apollo/shared';

export class AnalyticsService {
  async getInvestigationMetrics(): Promise<any> {
    const result = await database.query(`
      SELECT
        COUNT(*) FILTER (WHERE status = 'active') as active_investigations,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_investigations,
        COUNT(*) as total_investigations
      FROM operations
    `);
    return result.rows[0];
  }

  async getTargetStatistics(): Promise<any> {
    const result = await database.query(`
      SELECT
        COUNT(*) as total_targets,
        COUNT(*) FILTER (WHERE status = 'active') as active_targets,
        COUNT(*) FILTER (WHERE risk_level = 'high') as high_risk_targets
      FROM targets
    `);
    return result.rows[0];
  }

  async getUserActivityMetrics(timeRange: string = '7d'): Promise<any> {
    const interval = this.parseTimeRange(timeRange);
    const result = await database.query(
      `SELECT
        COUNT(DISTINCT user_id) as active_users,
        COUNT(*) as total_actions,
        COUNT(*) FILTER (WHERE action LIKE '%LOGIN%') as login_count
      FROM activity_logs
      WHERE timestamp > NOW() - INTERVAL '${interval}'`,
    );
    return result.rows[0];
  }

  async getSystemHealthMetrics(): Promise<any> {
    const dbSize = await database.query('SELECT pg_database_size(current_database()) as size');
    const tableStats = await database.query(`
      SELECT
        schemaname,
        tablename,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
      FROM pg_tables
      WHERE schemaname = 'public'
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
      LIMIT 10
    `);

    return {
      databaseSize: dbSize.rows[0]?.size,
      topTables: tableStats.rows,
    };
  }

  async getOperationTimeline(operationId: string): Promise<any[]> {
    const result = await database.query(
      `SELECT
        al.action,
        al.timestamp,
        u.username
      FROM activity_logs al
      JOIN users u ON al.user_id = u.id
      WHERE al.resource_type = 'operation' AND al.resource_id = $1
      ORDER BY al.timestamp DESC
      LIMIT 100`,
      [operationId],
    );
    return result.rows;
  }

  private parseTimeRange(timeRange: string): string {
    const map: Record<string, string> = {
      '1d': '1 day',
      '7d': '7 days',
      '30d': '30 days',
      '90d': '90 days',
    };
    return map[timeRange] || '7 days';
  }

  // Data aggregation methods
  async getDailyAggregations(startDate?: string, endDate?: string): Promise<any[]> {
    const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const end = endDate || new Date().toISOString().split('T')[0];

    const result = await database.query(
      `SELECT
        DATE(created_at) as date,
        COUNT(*) as total_operations,
        COUNT(*) FILTER (WHERE status = 'active') as active_operations,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_operations
      FROM operations
      WHERE DATE(created_at) BETWEEN $1 AND $2
      GROUP BY DATE(created_at)
      ORDER BY date DESC`,
      [start, end]
    );
    return result.rows;
  }

  async getAggregationSummary(): Promise<any> {
    const operationsResult = await database.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'active') as active,
        COUNT(*) FILTER (WHERE status = 'completed') as completed,
        COUNT(*) FILTER (WHERE status = 'pending') as pending
      FROM operations
    `);

    const targetsResult = await database.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE risk_level = 'high') as high_risk,
        COUNT(*) FILTER (WHERE risk_level = 'medium') as medium_risk,
        COUNT(*) FILTER (WHERE risk_level = 'low') as low_risk
      FROM targets
    `);

    const activityResult = await database.query(`
      SELECT COUNT(*) as total_actions
      FROM activity_logs
      WHERE timestamp > NOW() - INTERVAL '24 hours'
    `);

    return {
      operations: operationsResult.rows[0],
      targets: targetsResult.rows[0],
      recentActivity: activityResult.rows[0],
    };
  }

  // Reporting methods
  async getOperationsReport(status?: string, timeRange: string = '30d'): Promise<any> {
    const interval = this.parseTimeRange(timeRange);
    let query = `
      SELECT
        o.id,
        o.name,
        o.status,
        o.created_at,
        o.updated_at,
        COUNT(DISTINCT t.id) as target_count,
        COUNT(DISTINCT al.id) as activity_count
      FROM operations o
      LEFT JOIN targets t ON t.operation_id = o.id
      LEFT JOIN activity_logs al ON al.resource_type = 'operation' AND al.resource_id = o.id::text
      WHERE o.created_at > NOW() - INTERVAL '${interval}'
    `;

    const params: string[] = [];
    if (status) {
      params.push(status);
      query += ` AND o.status = $1`;
    }

    query += `
      GROUP BY o.id, o.name, o.status, o.created_at, o.updated_at
      ORDER BY o.updated_at DESC
      LIMIT 100
    `;

    const result = await database.query(query, params);
    return {
      timeRange,
      status: status || 'all',
      count: result.rows.length,
      operations: result.rows,
    };
  }

  async getTargetsReport(riskLevel?: string, limit: number = 20): Promise<any> {
    let query = `
      SELECT
        t.id,
        t.name,
        t.status,
        t.risk_level,
        t.created_at,
        t.updated_at,
        o.name as operation_name
      FROM targets t
      LEFT JOIN operations o ON t.operation_id = o.id
    `;

    const params: (string | number)[] = [];
    if (riskLevel) {
      params.push(riskLevel);
      query += ` WHERE t.risk_level = $1`;
    }

    params.push(limit);
    query += `
      ORDER BY t.updated_at DESC
      LIMIT $${params.length}
    `;

    const result = await database.query(query, params);
    return {
      riskLevel: riskLevel || 'all',
      count: result.rows.length,
      targets: result.rows,
    };
  }

  async getActivityReport(userId?: string, timeRange: string = '7d'): Promise<any> {
    const interval = this.parseTimeRange(timeRange);
    let query = `
      SELECT
        al.action,
        al.resource_type,
        al.timestamp,
        u.username,
        u.email
      FROM activity_logs al
      JOIN users u ON al.user_id = u.id
      WHERE al.timestamp > NOW() - INTERVAL '${interval}'
    `;

    const params: string[] = [];
    if (userId) {
      params.push(userId);
      query += ` AND al.user_id = $1`;
    }

    query += `
      ORDER BY al.timestamp DESC
      LIMIT 500
    `;

    const result = await database.query(query, params);

    // Aggregate by action type
    const actionCounts: Record<string, number> = {};
    for (const row of result.rows) {
      actionCounts[row.action] = (actionCounts[row.action] || 0) + 1;
    }

    return {
      timeRange,
      userId: userId || 'all',
      totalActions: result.rows.length,
      actionBreakdown: actionCounts,
      recentActivity: result.rows.slice(0, 50),
    };
  }
}

export const analyticsService = new AnalyticsService();
