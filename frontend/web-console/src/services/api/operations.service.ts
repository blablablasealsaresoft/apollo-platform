import apiClient from './client';
import { Operation, ApiResponse, FilterOptions, SortOptions, PaginationOptions } from '@types/index';

export interface CreateOperationData {
  operationName: string;
  codename?: string;
  description: string;
  investigationId: string;
  type: string;
  priority: string;
  startDate: string;
  endDate?: string;
  location?: {
    latitude: number;
    longitude: number;
    address: string;
    description?: string;
  };
  teamLeadId: string;
  teamMemberIds?: string[];
  objectives?: string[];
  budget?: number;
}

export interface CreateFieldReportData {
  operationId: string;
  summary: string;
  details: string;
  location?: string;
  classification: string;
}

class OperationsService {
  async getAll(
    filters?: FilterOptions,
    sort?: SortOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<Operation[]>> {
    return apiClient.get('/operations', { ...filters, ...sort, ...pagination });
  }

  async getById(id: string): Promise<ApiResponse<Operation>> {
    return apiClient.get(`/operations/${id}`);
  }

  async create(data: CreateOperationData): Promise<ApiResponse<Operation>> {
    return apiClient.post('/operations', data);
  }

  async update(id: string, data: Partial<CreateOperationData>): Promise<ApiResponse<Operation>> {
    return apiClient.patch(`/operations/${id}`, data);
  }

  async delete(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/operations/${id}`);
  }

  async updateStatus(id: string, status: string): Promise<ApiResponse> {
    return apiClient.patch(`/operations/${id}/status`, { status });
  }

  async getFieldReports(operationId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/operations/${operationId}/reports`);
  }

  async createFieldReport(data: CreateFieldReportData, files?: File[]): Promise<ApiResponse> {
    if (files && files.length > 0) {
      const formData = new FormData();
      Object.entries(data).forEach(([key, value]) => {
        formData.append(key, typeof value === 'object' ? JSON.stringify(value) : value);
      });
      files.forEach((file) => formData.append('files', file));
      return apiClient.upload('/operations/reports', formData);
    }
    return apiClient.post('/operations/reports', data);
  }

  async getTimeline(operationId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/operations/${operationId}/timeline`);
  }

  async addTimelineEvent(operationId: string, event: string, description: string, importance: string): Promise<ApiResponse> {
    return apiClient.post(`/operations/${operationId}/timeline`, {
      event,
      description,
      importance,
    });
  }

  async getRiskAssessment(operationId: string): Promise<ApiResponse<any>> {
    return apiClient.get(`/operations/${operationId}/risk-assessment`);
  }

  async updateRiskAssessment(operationId: string, data: any): Promise<ApiResponse> {
    return apiClient.patch(`/operations/${operationId}/risk-assessment`, data);
  }

  async addResource(operationId: string, resource: any): Promise<ApiResponse> {
    return apiClient.post(`/operations/${operationId}/resources`, resource);
  }

  async getActiveOperations(): Promise<ApiResponse<Operation[]>> {
    return apiClient.get('/operations/active');
  }
}

export const operationsService = new OperationsService();
export default operationsService;
