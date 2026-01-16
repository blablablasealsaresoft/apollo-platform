import { Router } from 'express';
import { intelligenceService } from '../services/intelligence.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const { reportIds } = req.body;
    const correlations = await intelligenceService.correlateReports(reportIds);
    res.json(createSuccessResponse(correlations));
  } catch (error) {
    next(error);
  }
});

export default router;
