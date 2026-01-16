import { InsightRequest, InsightResponse } from '../models/insight.model';

export async function generateInsights(payload: InsightRequest): Promise<InsightResponse> {
  // TODO: plug into analytics warehouse; placeholder data keeps UI unblocked
  return {
    investigationId: payload.investigationId,
    anomalies: Math.floor(Math.random() * 10),
    sentimentScore: Number((Math.random() * 2 - 1).toFixed(2)),
    keyFindings: [
      'Spike in Ruja communication',
      'Mixer usage detected on BTC',
      'Associate travel pattern anomaly',
    ],
  };
}
