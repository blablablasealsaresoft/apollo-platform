/**
 * Apollo Platform - Alert Routes
 * REST API endpoints for alert management
 */

import { Router, Request, Response, NextFunction } from 'express';
import { database, generateId, createSuccessResponse, logger } from '@apollo/shared';

const router = Router();

// Alert status enum
enum AlertStatus {
  NEW = 'new',
  ACKNOWLEDGED = 'acknowledged',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  DISMISSED = 'dismissed',
}

// Alert type enum
enum AlertType {
  SECURITY = 'security',
  INTELLIGENCE = 'intelligence',
  OPERATION = 'operation',
  SYSTEM = 'system',
  COMPLIANCE = 'compliance',
  FACIAL_MATCH = 'facial_match',
  TRANSACTION = 'transaction',
  SURVEILLANCE = 'surveillance',
}

// Get all alerts with filtering
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      status,
      severity,
      type,
      assignedTo,
      limit = 50,
      offset = 0,
      sortBy = 'created_at',
      sortOrder = 'desc',
    } = req.query;

    let query = 'SELECT * FROM alerts WHERE 1=1';
    const params: any[] = [];
    let paramIndex = 1;

    if (status) {
      query += ` AND status = $${paramIndex++}`;
      params.push(status);
    }

    if (severity) {
      query += ` AND severity = $${paramIndex++}`;
      params.push(severity);
    }

    if (type) {
      query += ` AND type = $${paramIndex++}`;
      params.push(type);
    }

    if (assignedTo) {
      query += ` AND assigned_to = $${paramIndex++}`;
      params.push(assignedTo);
    }

    // Validate sort column
    const validSortColumns = ['created_at', 'severity', 'status', 'type'];
    const sortColumn = validSortColumns.includes(sortBy as string) ? sortBy : 'created_at';
    const order = sortOrder === 'asc' ? 'ASC' : 'DESC';

    query += ` ORDER BY ${sortColumn} ${order} LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(Number(limit), Number(offset));

    const result = await database.query(query, params);

    // Get total count
    const countResult = await database.query(
      'SELECT COUNT(*) as total FROM alerts WHERE 1=1' +
      (status ? ` AND status = '${status}'` : '') +
      (severity ? ` AND severity = '${severity}'` : '') +
      (type ? ` AND type = '${type}'` : '') +
      (assignedTo ? ` AND assigned_to = '${assignedTo}'` : '')
    );

    res.json(createSuccessResponse({
      alerts: result.rows,
      pagination: {
        total: parseInt(countResult.rows[0].total),
        limit: Number(limit),
        offset: Number(offset),
      },
    }));
  } catch (error) {
    next(error);
  }
});

// Get alert statistics - MUST be before /:id route
router.get('/stats/summary', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const [statusStats, severityStats, typeStats, recentStats] = await Promise.all([
      database.query(`
        SELECT status, COUNT(*) as count
        FROM alerts
        GROUP BY status
      `),
      database.query(`
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE status NOT IN ('resolved', 'dismissed')
        GROUP BY severity
      `),
      database.query(`
        SELECT type, COUNT(*) as count
        FROM alerts
        WHERE status NOT IN ('resolved', 'dismissed')
        GROUP BY type
      `),
      database.query(`
        SELECT
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') as last_hour,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') as last_24h,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as last_7d
        FROM alerts
      `),
    ]);

    res.json(createSuccessResponse({
      byStatus: statusStats.rows.reduce((acc: any, row) => {
        acc[row.status] = parseInt(row.count);
        return acc;
      }, {}),
      bySeverity: severityStats.rows.reduce((acc: any, row) => {
        acc[row.severity] = parseInt(row.count);
        return acc;
      }, {}),
      byType: typeStats.rows.reduce((acc: any, row) => {
        acc[row.type] = parseInt(row.count);
        return acc;
      }, {}),
      recent: recentStats.rows[0],
    }));
  } catch (error) {
    next(error);
  }
});

// Bulk acknowledge alerts - MUST be before /:id route
router.post('/bulk/acknowledge', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { alertIds, userId } = req.body;

    if (!alertIds || !Array.isArray(alertIds) || alertIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'alertIds array is required' },
      });
    }

    const placeholders = alertIds.map((_, i) => `$${i + 3}`).join(',');
    const result = await database.query(
      `UPDATE alerts
       SET status = $1, acknowledged_at = NOW(), acknowledged_by = $2
       WHERE id IN (${placeholders}) AND status = 'new'
       RETURNING id`,
      [AlertStatus.ACKNOWLEDGED, userId, ...alertIds]
    );

    logger.info(`Bulk acknowledge: ${result.rows.length} alerts by ${userId}`);
    res.json(createSuccessResponse({
      acknowledged: result.rows.map(r => r.id),
      count: result.rows.length,
    }));
  } catch (error) {
    next(error);
  }
});

// Delete old resolved/dismissed alerts - MUST be before /:id route
router.delete('/cleanup', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { olderThanDays = 30 } = req.query;

    const result = await database.query(
      `DELETE FROM alerts
       WHERE status IN ('resolved', 'dismissed')
       AND (resolved_at < NOW() - INTERVAL '1 day' * $1
            OR dismissed_at < NOW() - INTERVAL '1 day' * $1)
       RETURNING id`,
      [Number(olderThanDays)]
    );

    logger.info(`Alert cleanup: ${result.rows.length} alerts deleted`);
    res.json(createSuccessResponse({
      deleted: result.rows.length,
      message: `Deleted ${result.rows.length} alerts older than ${olderThanDays} days`,
    }));
  } catch (error) {
    next(error);
  }
});

// Get alert by ID - must be after all specific routes
router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await database.query(
      'SELECT * FROM alerts WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

// Create new alert
router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      type,
      severity,
      title,
      message,
      source,
      relatedEntityType,
      relatedEntityId,
      actionRequired = false,
      assignedTo,
      metadata,
    } = req.body;

    // Validate required fields
    if (!type || !severity || !title || !message) {
      return res.status(400).json({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'Missing required fields' },
      });
    }

    const id = generateId();
    const result = await database.query(
      `INSERT INTO alerts (
        id, type, severity, title, message, source,
        related_entity_type, related_entity_id,
        action_required, assigned_to, status, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
      [
        id, type, severity, title, message, source || 'system',
        relatedEntityType || null, relatedEntityId || null,
        actionRequired, assignedTo || null, AlertStatus.NEW,
        metadata ? JSON.stringify(metadata) : null,
      ]
    );

    const alert = result.rows[0];
    logger.info(`Alert created: ${id} - ${title}`);

    res.status(201).json(createSuccessResponse(alert));
  } catch (error) {
    next(error);
  }
});

// Acknowledge alert
router.patch('/:id/acknowledge', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, notes } = req.body;

    const result = await database.query(
      `UPDATE alerts
       SET status = $1, acknowledged_at = NOW(), acknowledged_by = $2, notes = COALESCE(notes, '') || $3
       WHERE id = $4
       RETURNING *`,
      [AlertStatus.ACKNOWLEDGED, userId, notes ? `\n[Acknowledged]: ${notes}` : '', req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    logger.info(`Alert acknowledged: ${req.params.id} by ${userId}`);
    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

// Set alert to in progress
router.patch('/:id/progress', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, notes } = req.body;

    const result = await database.query(
      `UPDATE alerts
       SET status = $1, assigned_to = COALESCE(assigned_to, $2), notes = COALESCE(notes, '') || $3
       WHERE id = $4
       RETURNING *`,
      [AlertStatus.IN_PROGRESS, userId, notes ? `\n[In Progress]: ${notes}` : '', req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    logger.info(`Alert in progress: ${req.params.id}`);
    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

// Resolve alert
router.patch('/:id/resolve', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, resolution, notes } = req.body;

    const result = await database.query(
      `UPDATE alerts
       SET status = $1, resolved_at = NOW(), resolved_by = $2,
           resolution = $3, notes = COALESCE(notes, '') || $4
       WHERE id = $5
       RETURNING *`,
      [
        AlertStatus.RESOLVED,
        userId,
        resolution || 'Resolved',
        notes ? `\n[Resolved]: ${notes}` : '',
        req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    logger.info(`Alert resolved: ${req.params.id} by ${userId}`);
    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

// Dismiss alert
router.patch('/:id/dismiss', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId, reason } = req.body;

    const result = await database.query(
      `UPDATE alerts
       SET status = $1, dismissed_at = NOW(), dismissed_by = $2,
           notes = COALESCE(notes, '') || $3
       WHERE id = $4
       RETURNING *`,
      [
        AlertStatus.DISMISSED,
        userId,
        reason ? `\n[Dismissed]: ${reason}` : '',
        req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    logger.info(`Alert dismissed: ${req.params.id} by ${userId}`);
    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

// Assign alert to user
router.patch('/:id/assign', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { assignedTo, assignedBy } = req.body;

    if (!assignedTo) {
      return res.status(400).json({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'assignedTo is required' },
      });
    }

    const result = await database.query(
      `UPDATE alerts
       SET assigned_to = $1, notes = COALESCE(notes, '') || $2
       WHERE id = $3
       RETURNING *`,
      [assignedTo, `\n[Assigned to ${assignedTo} by ${assignedBy}]`, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Alert not found' },
      });
    }

    logger.info(`Alert assigned: ${req.params.id} to ${assignedTo}`);
    res.json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

export default router;
