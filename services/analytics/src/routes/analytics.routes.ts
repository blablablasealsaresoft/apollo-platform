import { Router } from 'express';
import { analyticsService } from '../services/analytics.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

router.get('/investigations', async (req, res, next) => {
  try {
    const metrics = await analyticsService.getInvestigationMetrics();
    res.json(createSuccessResponse(metrics));
  } catch (error) {
    next(error);
  }
});

router.get('/targets', async (req, res, next) => {
  try {
    const stats = await analyticsService.getTargetStatistics();
    res.json(createSuccessResponse(stats));
  } catch (error) {
    next(error);
  }
});

router.get('/users', async (req, res, next) => {
  try {
    const { timeRange = '7d' } = req.query;
    const metrics = await analyticsService.getUserActivityMetrics(timeRange as string);
    res.json(createSuccessResponse(metrics));
  } catch (error) {
    next(error);
  }
});

router.get('/system', async (req, res, next) => {
  try {
    const health = await analyticsService.getSystemHealthMetrics();
    res.json(createSuccessResponse(health));
  } catch (error) {
    next(error);
  }
});

router.get('/operations/:id/timeline', async (req, res, next) => {
  try {
    const timeline = await analyticsService.getOperationTimeline(req.params.id);
    res.json(createSuccessResponse(timeline));
  } catch (error) {
    next(error);
  }
});

export default router;
