import apiClient from './client';
import { User, ApiResponse } from '@types/index';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface MfaSetupResponse {
  secret: string;
  qrCode: string;
}

export interface MfaVerifyRequest {
  code: string;
  secret?: string;
}

export interface PasswordResetRequest {
  email: string;
}

export interface PasswordResetConfirm {
  token: string;
  newPassword: string;
}

class AuthService {
  async login(credentials: LoginCredentials): Promise<ApiResponse<{ user: User; token: string; refreshToken: string }>> {
    return apiClient.post('/auth/login', credentials);
  }

  async register(data: RegisterData): Promise<ApiResponse<{ user: User; token: string; refreshToken: string }>> {
    return apiClient.post('/auth/register', data);
  }

  async logout(): Promise<ApiResponse> {
    return apiClient.post('/auth/logout');
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    return apiClient.get('/auth/me');
  }

  async refreshToken(refreshToken: string): Promise<ApiResponse<{ token: string }>> {
    return apiClient.post('/auth/refresh', { refreshToken });
  }

  async setupMfa(): Promise<ApiResponse<MfaSetupResponse>> {
    return apiClient.post('/auth/mfa/setup');
  }

  async verifyMfa(data: MfaVerifyRequest): Promise<ApiResponse<{ verified: boolean }>> {
    return apiClient.post('/auth/mfa/verify', data);
  }

  async disableMfa(code: string): Promise<ApiResponse> {
    return apiClient.post('/auth/mfa/disable', { code });
  }

  async requestPasswordReset(data: PasswordResetRequest): Promise<ApiResponse> {
    return apiClient.post('/auth/password/reset-request', data);
  }

  async resetPassword(data: PasswordResetConfirm): Promise<ApiResponse> {
    return apiClient.post('/auth/password/reset', data);
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<ApiResponse> {
    return apiClient.post('/auth/password/change', { currentPassword, newPassword });
  }
}

export const authService = new AuthService();
export default authService;
