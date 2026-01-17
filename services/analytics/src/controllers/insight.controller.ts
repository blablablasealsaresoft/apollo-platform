import { Request, Response, NextFunction } from 'express';
import { InsightRequest, InsightResponse } from '../models/insight.model';
import { generateInsights } from '../processors/insight.processor';
import { createSuccessResponse } from '@apollo/shared';

class InsightController {
  async getCaseInsights(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload: InsightRequest = {
        investigationId: req.params.id,
        timeframeHours: Number(req.query.hours ?? 24),
      };

      const result: InsightResponse = await generateInsights(payload);
      res.json(createSuccessResponse(result));
    } catch (error) {
      next(error);
    }
  }
}

export default new InsightController();
