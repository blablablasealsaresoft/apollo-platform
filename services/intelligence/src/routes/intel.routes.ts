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

router.put('/:id', async (req, res, next) => {
  try {
    const report = await intelligenceService.updateReport(req.params.id, req.body);
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    await intelligenceService.deleteReport(req.params.id);
    res.status(204).send();
  } catch (error) {
    next(error);
  }
});

export default router;
