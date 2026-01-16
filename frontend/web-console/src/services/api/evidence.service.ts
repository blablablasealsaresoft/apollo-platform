import apiClient from './client';
import { Evidence, ApiResponse, FilterOptions, SortOptions, PaginationOptions } from '@types/index';

export interface CreateEvidenceData {
  investigationId: string;
  type: string;
  title: string;
  description: string;
  collectedAt: string;
  location?: string;
  tags?: string[];
  classification: string;
  metadata?: Record<string, any>;
}

export interface UpdateEvidenceData extends Partial<CreateEvidenceData> {
  verified?: boolean;
}

class EvidenceService {
  async getAll(
    filters?: FilterOptions,
    sort?: SortOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<Evidence[]>> {
    return apiClient.get('/evidence', { ...filters, ...sort, ...pagination });
  }

  async getById(id: string): Promise<ApiResponse<Evidence>> {
    return apiClient.get(`/evidence/${id}`);
  }

  async getByInvestigation(investigationId: string): Promise<ApiResponse<Evidence[]>> {
    return apiClient.get(`/investigations/${investigationId}/evidence`);
  }

  async create(data: CreateEvidenceData, file?: File): Promise<ApiResponse<Evidence>> {
    if (file) {
      const formData = new FormData();
      formData.append('file', file);
      Object.entries(data).forEach(([key, value]) => {
        formData.append(key, typeof value === 'object' ? JSON.stringify(value) : value);
      });
      return apiClient.upload('/evidence', formData);
    }
    return apiClient.post('/evidence', data);
  }

  async update(id: string, data: UpdateEvidenceData): Promise<ApiResponse<Evidence>> {
    return apiClient.patch(`/evidence/${id}`, data);
  }

  async delete(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/evidence/${id}`);
  }

  async uploadFile(evidenceId: string, file: File): Promise<ApiResponse<{ fileUrl: string }>> {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.upload(`/evidence/${evidenceId}/file`, formData);
  }

  async downloadFile(evidenceId: string, fileName: string): Promise<void> {
    return apiClient.download(`/evidence/${evidenceId}/file`, fileName);
  }

  async getChainOfCustody(evidenceId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/evidence/${evidenceId}/chain-of-custody`);
  }

  async addChainOfCustodyEntry(
    evidenceId: string,
    action: string,
    location: string,
    notes?: string
  ): Promise<ApiResponse> {
    return apiClient.post(`/evidence/${evidenceId}/chain-of-custody`, {
      action,
      location,
      notes,
    });
  }

  async verify(evidenceId: string): Promise<ApiResponse> {
    return apiClient.post(`/evidence/${evidenceId}/verify`);
  }

  async addTags(evidenceId: string, tags: string[]): Promise<ApiResponse> {
    return apiClient.post(`/evidence/${evidenceId}/tags`, { tags });
  }

  async removeTags(evidenceId: string, tags: string[]): Promise<ApiResponse> {
    return apiClient.delete(`/evidence/${evidenceId}/tags`, { data: { tags } });
  }

  async search(query: string, filters?: FilterOptions): Promise<ApiResponse<Evidence[]>> {
    return apiClient.get('/evidence/search', { q: query, ...filters });
  }
}

export const evidenceService = new EvidenceService();
export default evidenceService;
