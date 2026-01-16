import apiClient from './client';
import { FacialMatch, FacialSearchResult, ApiResponse } from '@types/index';

export interface FacialSearchRequest {
  threshold?: number;
  maxResults?: number;
}

// Base path for facial recognition API endpoints
const BASE_PATH = '/v1/facial';

class FacialService {
  async searchByImage(image: File, options?: FacialSearchRequest): Promise<ApiResponse<FacialSearchResult>> {
    const formData = new FormData();
    formData.append('image', image);
    if (options?.threshold) formData.append('threshold', options.threshold.toString());
    if (options?.maxResults) formData.append('maxResults', options.maxResults.toString());
    return apiClient.upload(`${BASE_PATH}/search`, formData);
  }

  async searchByImageUrl(imageUrl: string, options?: FacialSearchRequest): Promise<ApiResponse<FacialSearchResult>> {
    return apiClient.post(`${BASE_PATH}/search/url`, { imageUrl, ...options });
  }

  async getMatches(targetId?: string): Promise<ApiResponse<FacialMatch[]>> {
    return apiClient.get(`${BASE_PATH}/matches`, targetId ? { targetId } : undefined);
  }

  async getMatchById(id: string): Promise<ApiResponse<FacialMatch>> {
    return apiClient.get(`${BASE_PATH}/matches/${id}`);
  }

  async verifyMatch(matchId: string, verified: boolean, notes?: string): Promise<ApiResponse> {
    return apiClient.patch(`${BASE_PATH}/matches/${matchId}`, { verified, notes });
  }

  async enrollFace(targetId: string, image: File, targetName?: string): Promise<ApiResponse<{ faceId: string }>> {
    const formData = new FormData();
    formData.append('image', image);
    formData.append('targetId', targetId);
    if (targetName) formData.append('targetName', targetName);
    return apiClient.upload(`${BASE_PATH}/enroll`, formData);
  }

  async deleteFace(targetId: string, faceId: string): Promise<ApiResponse> {
    return apiClient.delete(`${BASE_PATH}/${targetId}/faces/${faceId}`);
  }

  async getLiveFeedMatches(cameraId: string): Promise<ApiResponse<FacialMatch[]>> {
    return apiClient.get(`${BASE_PATH}/live-feed/${cameraId}/matches`);
  }

  async getFaceDatabase(): Promise<ApiResponse<any[]>> {
    return apiClient.get(`${BASE_PATH}/database`);
  }

  async compareFaces(image1: File, image2: File): Promise<ApiResponse<{ match: boolean; confidence: number }>> {
    const formData = new FormData();
    formData.append('image1', image1);
    formData.append('image2', image2);
    return apiClient.upload(`${BASE_PATH}/compare`, formData);
  }

  async detectFaces(image: File, returnLandmarks: boolean = false): Promise<ApiResponse<any>> {
    const formData = new FormData();
    formData.append('image', image);
    formData.append('return_landmarks', returnLandmarks.toString());
    return apiClient.upload(`${BASE_PATH}/detect`, formData);
  }

  async getStats(): Promise<ApiResponse<any>> {
    return apiClient.get(`${BASE_PATH}/stats`);
  }

  async healthCheck(): Promise<ApiResponse<any>> {
    return apiClient.get(`${BASE_PATH}/health`);
  }
}

export const facialService = new FacialService();
export default facialService;
