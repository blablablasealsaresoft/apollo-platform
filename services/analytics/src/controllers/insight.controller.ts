import { Request, Response } from 'express';
import { InsightRequest, InsightResponse } from '../models/insight.model';
import { generateInsights } from '../processors/insight.processor';

class InsightController {
  async getCaseInsights(req: Request, res: Response) {
    const payload: InsightRequest = {
      investigationId: req.params.id,
      timeframeHours: Number(req.query.hours ?? 24),
    };

    const result: InsightResponse = await generateInsights(payload);
    res.json(result);
  }
}

export default new InsightController();
