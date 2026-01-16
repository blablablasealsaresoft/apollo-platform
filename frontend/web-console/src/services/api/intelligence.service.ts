import apiClient from './client';
import { IntelligenceReport, ApiResponse, FilterOptions, SortOptions, PaginationOptions } from '@types/index';

export interface CreateIntelligenceData {
  title: string;
  summary: string;
  content: string;
  type: string;
  source: {
    name: string;
    type: string;
    reliability: number;
  };
  confidence: string;
  classification: string;
  relatedTargets?: string[];
  relatedInvestigations?: string[];
  tags?: string[];
  validFrom: string;
  validUntil?: string;
}

class IntelligenceService {
  async getAll(
    filters?: FilterOptions,
    sort?: SortOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<IntelligenceReport[]>> {
    return apiClient.get('/intelligence', { ...filters, ...sort, ...pagination });
  }

  async getById(id: string): Promise<ApiResponse<IntelligenceReport>> {
    return apiClient.get(`/intelligence/${id}`);
  }

  async create(data: CreateIntelligenceData): Promise<ApiResponse<IntelligenceReport>> {
    return apiClient.post('/intelligence', data);
  }

  async update(id: string, data: Partial<CreateIntelligenceData>): Promise<ApiResponse<IntelligenceReport>> {
    return apiClient.patch(`/intelligence/${id}`, data);
  }

  async delete(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/intelligence/${id}`);
  }

  async verify(id: string): Promise<ApiResponse> {
    return apiClient.post(`/intelligence/${id}/verify`);
  }

  async getCorrelations(id: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/intelligence/${id}/correlations`);
  }

  async findCorrelations(targetId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/intelligence/correlations/target/${targetId}`);
  }

  async search(query: string, filters?: FilterOptions): Promise<ApiResponse<IntelligenceReport[]>> {
    return apiClient.get('/intelligence/search', { q: query, ...filters });
  }

  async uploadAttachment(id: string, file: File): Promise<ApiResponse> {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.upload(`/intelligence/${id}/attachments`, formData);
  }
}

export const intelligenceService = new IntelligenceService();
export default intelligenceService;
