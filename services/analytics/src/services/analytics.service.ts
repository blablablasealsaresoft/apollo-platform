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
}

export const analyticsService = new AnalyticsService();
