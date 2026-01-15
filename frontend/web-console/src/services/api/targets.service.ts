import apiClient from './client';
import { Target, ApiResponse, FilterOptions, SortOptions, PaginationOptions, NetworkNode, NetworkEdge } from '@types/index';

export interface CreateTargetData {
  firstName: string;
  lastName: string;
  aliases?: string[];
  dateOfBirth?: string;
  nationality?: string;
  gender?: string;
  riskLevel: string;
  status: string;
  knownAddresses?: any[];
  phoneNumbers?: string[];
  emailAddresses?: string[];
  socialMedia?: any[];
  notes?: string;
}

export interface UpdateTargetData extends Partial<CreateTargetData> {}

class TargetsService {
  async getAll(
    filters?: FilterOptions,
    sort?: SortOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<Target[]>> {
    return apiClient.get('/targets', { ...filters, ...sort, ...pagination });
  }

  async getById(id: string): Promise<ApiResponse<Target>> {
    return apiClient.get(`/targets/${id}`);
  }

  async create(data: CreateTargetData): Promise<ApiResponse<Target>> {
    return apiClient.post('/targets', data);
  }

  async update(id: string, data: UpdateTargetData): Promise<ApiResponse<Target>> {
    return apiClient.patch(`/targets/${id}`, data);
  }

  async delete(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/targets/${id}`);
  }

  async uploadPhoto(targetId: string, file: File): Promise<ApiResponse<{ photoUrl: string }>> {
    const formData = new FormData();
    formData.append('photo', file);
    return apiClient.upload(`/targets/${targetId}/photo`, formData);
  }

  async getNetwork(targetId: string, depth: number = 2): Promise<ApiResponse<{ nodes: NetworkNode[]; edges: NetworkEdge[] }>> {
    return apiClient.get(`/targets/${targetId}/network`, { depth });
  }

  async getLocationHistory(targetId: string, dateFrom?: string, dateTo?: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/targets/${targetId}/locations`, { dateFrom, dateTo });
  }

  async getKnownAssociates(targetId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/targets/${targetId}/associates`);
  }

  async addAssociate(targetId: string, associateId: string, relationship: string): Promise<ApiResponse> {
    return apiClient.post(`/targets/${targetId}/associates`, { associateId, relationship });
  }

  async getCriminalHistory(targetId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/targets/${targetId}/criminal-history`);
  }

  async getFinancialProfile(targetId: string): Promise<ApiResponse<any>> {
    return apiClient.get(`/targets/${targetId}/financial-profile`);
  }

  async search(query: string): Promise<ApiResponse<Target[]>> {
    return apiClient.get('/targets/search', { q: query });
  }

  async exportTarget(targetId: string, format: 'pdf' | 'excel'): Promise<void> {
    return apiClient.download(`/targets/${targetId}/export?format=${format}`, `target-${targetId}.${format}`);
  }
}

export const targetsService = new TargetsService();
export default targetsService;
