import apiClient from './client';
import { DashboardStats, ActivityItem, Alert, ApiResponse } from '@types/index';

class DashboardService {
  async getStats(): Promise<ApiResponse<DashboardStats>> {
    return apiClient.get('/dashboard/stats');
  }

  async getRecentActivity(limit: number = 20): Promise<ApiResponse<ActivityItem[]>> {
    return apiClient.get('/dashboard/activity', { limit });
  }

  async getAlerts(status?: string): Promise<ApiResponse<Alert[]>> {
    return apiClient.get('/dashboard/alerts', status ? { status } : undefined);
  }

  async acknowledgeAlert(alertId: string): Promise<ApiResponse> {
    return apiClient.post(`/dashboard/alerts/${alertId}/acknowledge`);
  }

  async resolveAlert(alertId: string, notes?: string): Promise<ApiResponse> {
    return apiClient.post(`/dashboard/alerts/${alertId}/resolve`, { notes });
  }

  async dismissAlert(alertId: string): Promise<ApiResponse> {
    return apiClient.post(`/dashboard/alerts/${alertId}/dismiss`);
  }

  async getNotifications(unreadOnly: boolean = false): Promise<ApiResponse<any[]>> {
    return apiClient.get('/dashboard/notifications', { unreadOnly });
  }

  async markNotificationRead(notificationId: string): Promise<ApiResponse> {
    return apiClient.patch(`/dashboard/notifications/${notificationId}`, { read: true });
  }

  async markAllNotificationsRead(): Promise<ApiResponse> {
    return apiClient.post('/dashboard/notifications/mark-all-read');
  }
}

export const dashboardService = new DashboardService();
export default dashboardService;
