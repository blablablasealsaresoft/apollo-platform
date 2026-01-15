import { Router } from 'express';
import { intelligenceService } from '../services/intelligence.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const report = await intelligenceService.createReport(req.body);
    res.status(201).json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const reports = await intelligenceService.listReports(req.query as any);
    res.json(createSuccessResponse(reports));
  } catch (error) {
    next(error);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    const report = await intelligenceService.getReportById(req.params.id);
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

router.get('/:id/confidence', async (req, res, next) => {
  try {
    const score = await intelligenceService.scoreConfidence(req.params.id);
    res.json(createSuccessResponse({ score }));
  } catch (error) {
    next(error);
  }
});

export default router;
