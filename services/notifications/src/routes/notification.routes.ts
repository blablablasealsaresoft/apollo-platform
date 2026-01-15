import { Router } from 'express';
import { database, generateId, createSuccessResponse, NotificationType } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const { userId, type, title, message, metadata } = req.body;
    const id = generateId();
    const result = await database.query(
      'INSERT INTO notifications (id, user_id, type, title, message, metadata) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [id, userId, type, title, message, metadata ? JSON.stringify(metadata) : null],
    );
    res.status(201).json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

router.get('/user/:userId', async (req, res, next) => {
  try {
    const result = await database.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.params.userId],
    );
    res.json(createSuccessResponse(result.rows));
  } catch (error) {
    next(error);
  }
});

router.patch('/:id/read', async (req, res, next) => {
  try {
    await database.query('UPDATE notifications SET is_read = true WHERE id = $1', [req.params.id]);
    res.json(createSuccessResponse({ message: 'Notification marked as read' }));
  } catch (error) {
    next(error);
  }
});

export default router;
