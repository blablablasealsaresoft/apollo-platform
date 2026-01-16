import apiClient from './client';
import { ApiResponse } from '@types/index';

export interface OverviewStats {
  totalInvestigations: number;
  investigationChange: number;
  activeTargets: number;
  targetChange: number;
  alertsResolved: number;
  alertChange: number;
  evidenceCollected: number;
  evidenceChange: number;
}

export interface TrendData {
  month: string;
  opened: number;
  closed: number;
  active: number;
}

export interface AlertTypeData {
  name: string;
  value: number;
  color: string;
}

export interface RiskDistributionData {
  level: string;
  count: number;
  color: string;
}

export interface ActivityData {
  hour: string;
  alerts: number;
  logins: number;
  searches: number;
}

export interface GeoDistributionData {
  region: string;
  targets: number;
  operations: number;
}

export interface EvidenceTypeData {
  type: string;
  count: number;
}

export interface HeatmapData {
  day: string;
  hour: number;
  value: number;
}

class AnalyticsService {
  async getOverviewStats(dateRange: string): Promise<ApiResponse<OverviewStats>> {
    try {
      return await apiClient.get('/analytics/overview', { dateRange });
    } catch {
      // Return mock data for development
      return {
        success: true,
        data: {
          totalInvestigations: 156,
          investigationChange: 12.5,
          activeTargets: 89,
          targetChange: -3.2,
          alertsResolved: 324,
          alertChange: 28.4,
          evidenceCollected: 1247,
          evidenceChange: 15.8,
        },
      };
    }
  }

  async getInvestigationTrends(dateRange: string): Promise<ApiResponse<TrendData[]>> {
    try {
      return await apiClient.get('/analytics/investigations/trends', { dateRange });
    } catch {
      return {
        success: true,
        data: [
          { month: 'Jan', opened: 12, closed: 8, active: 45 },
          { month: 'Feb', opened: 15, closed: 10, active: 50 },
          { month: 'Mar', opened: 18, closed: 14, active: 54 },
          { month: 'Apr', opened: 14, closed: 12, active: 56 },
          { month: 'May', opened: 20, closed: 16, active: 60 },
          { month: 'Jun', opened: 22, closed: 18, active: 64 },
          { month: 'Jul', opened: 19, closed: 15, active: 68 },
          { month: 'Aug', opened: 25, closed: 20, active: 73 },
          { month: 'Sep', opened: 21, closed: 17, active: 77 },
          { month: 'Oct', opened: 28, closed: 22, active: 83 },
          { month: 'Nov', opened: 24, closed: 19, active: 88 },
          { month: 'Dec', opened: 18, closed: 15, active: 91 },
        ],
      };
    }
  }

  async getAlertsByType(): Promise<ApiResponse<AlertTypeData[]>> {
    try {
      return await apiClient.get('/analytics/alerts/by-type');
    } catch {
      return {
        success: true,
        data: [
          { name: 'Security', value: 45, color: '#ef4444' },
          { name: 'Intelligence', value: 32, color: '#6366f1' },
          { name: 'Transaction', value: 28, color: '#22c55e' },
          { name: 'Facial Match', value: 18, color: '#f59e0b' },
          { name: 'Operation', value: 15, color: '#8b5cf6' },
          { name: 'System', value: 8, color: '#06b6d4' },
        ],
      };
    }
  }

  async getTargetRiskDistribution(): Promise<ApiResponse<RiskDistributionData[]>> {
    try {
      return await apiClient.get('/analytics/targets/risk-distribution');
    } catch {
      return {
        success: true,
        data: [
          { level: 'Extreme', count: 12, color: '#ef4444' },
          { level: 'High', count: 28, color: '#f59e0b' },
          { level: 'Medium', count: 45, color: '#6366f1' },
          { level: 'Low', count: 34, color: '#22c55e' },
        ],
      };
    }
  }

  async getActivityByHour(): Promise<ApiResponse<ActivityData[]>> {
    try {
      return await apiClient.get('/analytics/activity/by-hour');
    } catch {
      return {
        success: true,
        data: Array.from({ length: 24 }, (_, i) => ({
          hour: `${i.toString().padStart(2, '0')}:00`,
          alerts: Math.floor(Math.random() * 50) + 10,
          logins: Math.floor(Math.random() * 30) + 5,
          searches: Math.floor(Math.random() * 100) + 20,
        })),
      };
    }
  }

  async getGeographicDistribution(): Promise<ApiResponse<GeoDistributionData[]>> {
    try {
      return await apiClient.get('/analytics/geographic-distribution');
    } catch {
      return {
        success: true,
        data: [
          { region: 'Europe', targets: 45, operations: 28 },
          { region: 'Middle East', targets: 32, operations: 18 },
          { region: 'Asia Pacific', targets: 28, operations: 15 },
          { region: 'North America', targets: 22, operations: 12 },
          { region: 'South America', targets: 15, operations: 8 },
          { region: 'Africa', targets: 12, operations: 6 },
        ],
      };
    }
  }

  async getEvidenceByType(): Promise<ApiResponse<EvidenceTypeData[]>> {
    try {
      return await apiClient.get('/analytics/evidence/by-type');
    } catch {
      return {
        success: true,
        data: [
          { type: 'Documents', count: 456 },
          { type: 'Photos', count: 324 },
          { type: 'Digital', count: 287 },
          { type: 'Financial', count: 198 },
          { type: 'Communications', count: 156 },
          { type: 'Videos', count: 89 },
          { type: 'Audio', count: 67 },
        ],
      };
    }
  }

  async getActivityHeatmap(dateRange: string): Promise<ApiResponse<HeatmapData[]>> {
    try {
      return await apiClient.get('/analytics/activity/heatmap', { dateRange });
    } catch {
      const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      const data: HeatmapData[] = [];
      days.forEach((day) => {
        for (let hour = 0; hour < 24; hour++) {
          data.push({
            day,
            hour,
            value: Math.floor(Math.random() * 100),
          });
        }
      });
      return { success: true, data };
    }
  }

  async getPerformanceMetrics(dateRange: string): Promise<ApiResponse<any>> {
    try {
      return await apiClient.get('/analytics/performance', { dateRange });
    } catch {
      return {
        success: true,
        data: {
          avgCaseResolutionTime: 14.5,
          caseResolutionChange: -8.3,
          successRate: 87.5,
          successRateChange: 5.2,
          evidenceQuality: 94.2,
          evidenceQualityChange: 2.1,
          teamEfficiency: 91.8,
          teamEfficiencyChange: 3.4,
        },
      };
    }
  }

  async exportAnalytics(format: 'pdf' | 'csv' | 'excel', dateRange: string): Promise<void> {
    return apiClient.download(
      `/analytics/export?format=${format}&dateRange=${dateRange}`,
      `analytics-report-${dateRange}.${format}`
    );
  }
}

export const analyticsService = new AnalyticsService();
export default analyticsService;
