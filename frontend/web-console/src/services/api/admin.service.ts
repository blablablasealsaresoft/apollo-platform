import apiClient from './client';
import { User, AuditLog, ApiResponse, PaginationOptions } from '@types/index';

export interface CreateUserData {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: string;
  department?: string;
  badgeNumber?: string;
}

export interface UpdateUserData extends Partial<Omit<CreateUserData, 'password'>> {
  active?: boolean;
}

class AdminService {
  async getUsers(pagination?: PaginationOptions): Promise<ApiResponse<User[]>> {
    return apiClient.get('/admin/users', pagination);
  }

  async getUserById(id: string): Promise<ApiResponse<User>> {
    return apiClient.get(`/admin/users/${id}`);
  }

  async createUser(data: CreateUserData): Promise<ApiResponse<User>> {
    return apiClient.post('/admin/users', data);
  }

  async updateUser(id: string, data: UpdateUserData): Promise<ApiResponse<User>> {
    return apiClient.patch(`/admin/users/${id}`, data);
  }

  async deleteUser(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/users/${id}`);
  }

  async resetUserPassword(id: string, newPassword: string): Promise<ApiResponse> {
    return apiClient.post(`/admin/users/${id}/reset-password`, { newPassword });
  }

  async getAuditLogs(filters?: any, pagination?: PaginationOptions): Promise<ApiResponse<AuditLog[]>> {
    return apiClient.get('/admin/audit-logs', { ...filters, ...pagination });
  }

  async getSystemConfig(): Promise<ApiResponse<any>> {
    return apiClient.get('/admin/config');
  }

  async updateSystemConfig(config: any): Promise<ApiResponse> {
    return apiClient.patch('/admin/config', config);
  }

  async getApiKeys(): Promise<ApiResponse<any[]>> {
    return apiClient.get('/admin/api-keys');
  }

  async createApiKey(name: string, permissions: string[]): Promise<ApiResponse<{ key: string }>> {
    return apiClient.post('/admin/api-keys', { name, permissions });
  }

  async revokeApiKey(keyId: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/api-keys/${keyId}`);
  }

  async getSystemHealth(): Promise<ApiResponse<any>> {
    return apiClient.get('/admin/health');
  }

  async getSystemMetrics(): Promise<ApiResponse<any>> {
    return apiClient.get('/admin/metrics');
  }

  async exportData(entityType: string, filters?: any): Promise<void> {
    return apiClient.download(`/admin/export/${entityType}`, `${entityType}-export.json`);
  }
}

export const adminService = new AdminService();
export default adminService;
