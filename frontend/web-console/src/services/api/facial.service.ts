import apiClient from './client';
import { FacialMatch, FacialSearchResult, ApiResponse } from '@types/index';

export interface FacialSearchRequest {
  threshold?: number;
  maxResults?: number;
}

class FacialService {
  async searchByImage(image: File, options?: FacialSearchRequest): Promise<ApiResponse<FacialSearchResult>> {
    const formData = new FormData();
    formData.append('image', image);
    if (options?.threshold) formData.append('threshold', options.threshold.toString());
    if (options?.maxResults) formData.append('maxResults', options.maxResults.toString());
    return apiClient.upload('/facial/search', formData);
  }

  async searchByImageUrl(imageUrl: string, options?: FacialSearchRequest): Promise<ApiResponse<FacialSearchResult>> {
    return apiClient.post('/facial/search/url', { imageUrl, ...options });
  }

  async getMatches(targetId?: string): Promise<ApiResponse<FacialMatch[]>> {
    return apiClient.get('/facial/matches', targetId ? { targetId } : undefined);
  }

  async getMatchById(id: string): Promise<ApiResponse<FacialMatch>> {
    return apiClient.get(`/facial/matches/${id}`);
  }

  async verifyMatch(matchId: string, verified: boolean, notes?: string): Promise<ApiResponse> {
    return apiClient.patch(`/facial/matches/${matchId}`, { verified, notes });
  }

  async enrollFace(targetId: string, image: File): Promise<ApiResponse<{ faceId: string }>> {
    const formData = new FormData();
    formData.append('image', image);
    formData.append('targetId', targetId);
    return apiClient.upload('/facial/enroll', formData);
  }

  async deleteFace(targetId: string, faceId: string): Promise<ApiResponse> {
    return apiClient.delete(`/facial/${targetId}/faces/${faceId}`);
  }

  async getLiveFeedMatches(cameraId: string): Promise<ApiResponse<FacialMatch[]>> {
    return apiClient.get(`/facial/live-feed/${cameraId}/matches`);
  }

  async getFaceDatabase(): Promise<ApiResponse<any[]>> {
    return apiClient.get('/facial/database');
  }

  async compareFaces(image1: File, image2: File): Promise<ApiResponse<{ match: boolean; confidence: number }>> {
    const formData = new FormData();
    formData.append('image1', image1);
    formData.append('image2', image2);
    return apiClient.upload('/facial/compare', formData);
  }
}

export const facialService = new FacialService();
export default facialService;
