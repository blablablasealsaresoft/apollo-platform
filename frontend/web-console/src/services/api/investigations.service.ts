import apiClient from './client';
import { Investigation, ApiResponse, FilterOptions, SortOptions, PaginationOptions } from '@types/index';

export interface CreateInvestigationData {
  title: string;
  description: string;
  priority: string;
  classification: string;
  leadInvestigatorId: string;
  teamMemberIds?: string[];
  targetIds?: string[];
  startDate: string;
  estimatedEndDate?: string;
  budget?: number;
  tags?: string[];
  notes?: string;
}

export interface UpdateInvestigationData extends Partial<CreateInvestigationData> {
  status?: string;
}

class InvestigationsService {
  async getAll(
    filters?: FilterOptions,
    sort?: SortOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<Investigation[]>> {
    return apiClient.get('/investigations', { ...filters, ...sort, ...pagination });
  }

  async getById(id: string): Promise<ApiResponse<Investigation>> {
    return apiClient.get(`/investigations/${id}`);
  }

  async create(data: CreateInvestigationData): Promise<ApiResponse<Investigation>> {
    return apiClient.post('/investigations', data);
  }

  async update(id: string, data: UpdateInvestigationData): Promise<ApiResponse<Investigation>> {
    return apiClient.patch(`/investigations/${id}`, data);
  }

  async delete(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/investigations/${id}`);
  }

  async addTarget(investigationId: string, targetId: string): Promise<ApiResponse> {
    return apiClient.post(`/investigations/${investigationId}/targets`, { targetId });
  }

  async removeTarget(investigationId: string, targetId: string): Promise<ApiResponse> {
    return apiClient.delete(`/investigations/${investigationId}/targets/${targetId}`);
  }

  async addTeamMember(investigationId: string, userId: string): Promise<ApiResponse> {
    return apiClient.post(`/investigations/${investigationId}/team`, { userId });
  }

  async removeTeamMember(investigationId: string, userId: string): Promise<ApiResponse> {
    return apiClient.delete(`/investigations/${investigationId}/team/${userId}`);
  }

  async getTimeline(investigationId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/investigations/${investigationId}/timeline`);
  }

  async addNote(investigationId: string, note: string): Promise<ApiResponse> {
    return apiClient.post(`/investigations/${investigationId}/notes`, { note });
  }

  async exportInvestigation(investigationId: string, format: 'pdf' | 'excel'): Promise<void> {
    return apiClient.download(`/investigations/${investigationId}/export?format=${format}`, `investigation-${investigationId}.${format}`);
  }
}

export const investigationsService = new InvestigationsService();
export default investigationsService;
