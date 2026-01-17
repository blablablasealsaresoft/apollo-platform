import { Router } from 'express';
import { analyticsService } from '../services/analytics.service';
import { createSuccessResponse } from '@apollo/shared';
import insightController from '../controllers/insight.controller';

const router = Router();

// Investigation metrics
router.get('/investigations', async (req, res, next) => {
  try {
    const metrics = await analyticsService.getInvestigationMetrics();
    res.json(createSuccessResponse(metrics));
  } catch (error) {
    next(error);
  }
});

// Insights endpoint - uses the InsightController
router.get('/insights/:id', insightController.getCaseInsights.bind(insightController));

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

// Data aggregation endpoints
router.get('/aggregations/daily', async (req, res, next) => {
  try {
    const { startDate, endDate } = req.query;
    const data = await analyticsService.getDailyAggregations(
      startDate as string | undefined,
      endDate as string | undefined
    );
    res.json(createSuccessResponse(data));
  } catch (error) {
    next(error);
  }
});

router.get('/aggregations/summary', async (req, res, next) => {
  try {
    const summary = await analyticsService.getAggregationSummary();
    res.json(createSuccessResponse(summary));
  } catch (error) {
    next(error);
  }
});

// Reporting endpoints
router.get('/reports/operations', async (req, res, next) => {
  try {
    const { status, timeRange = '30d' } = req.query;
    const report = await analyticsService.getOperationsReport(
      status as string | undefined,
      timeRange as string
    );
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

router.get('/reports/targets', async (req, res, next) => {
  try {
    const { riskLevel, limit = '20' } = req.query;
    const report = await analyticsService.getTargetsReport(
      riskLevel as string | undefined,
      parseInt(limit as string, 10)
    );
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

router.get('/reports/activity', async (req, res, next) => {
  try {
    const { userId, timeRange = '7d' } = req.query;
    const report = await analyticsService.getActivityReport(
      userId as string | undefined,
      timeRange as string
    );
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

export default router;
