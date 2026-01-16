export interface InsightRequest {
  investigationId: string;
  timeframeHours: number;
}

export interface InsightResponse {
  investigationId: string;
  anomalies: number;
  sentimentScore: number;
  keyFindings: string[];
}
