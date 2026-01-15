import { Router } from 'express';
import { database, generateId, createSuccessResponse } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const { operationId, title, content, authorId } = req.body;
    const id = generateId();
    const result = await database.query(
      'INSERT INTO field_reports (id, operation_id, title, content, author_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [id, operationId, title, content, authorId],
    );
    res.status(201).json(createSuccessResponse(result.rows[0]));
  } catch (error) {
    next(error);
  }
});

router.get('/operation/:operationId', async (req, res, next) => {
  try {
    const result = await database.query(
      'SELECT * FROM field_reports WHERE operation_id = $1 ORDER BY created_at DESC',
      [req.params.operationId],
    );
    res.json(createSuccessResponse(result.rows));
  } catch (error) {
    next(error);
  }
});

export default router;
