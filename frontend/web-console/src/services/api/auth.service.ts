import apiClient from './client';
import { User, ApiResponse } from '@types/index';

export interface LoginCredentials {
  email: string;
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

export interface BiometricLoginData {
  type: string;
  biometricData: string;
  livenessProof?: string;
}

export interface MfaVerificationData {
  sessionId: string;
  code: string;
}

export interface BiometricEnrollment {
  type: string;
  template: string;
  password: string;
  qualityScore: number;
  deviceId?: string;
}

export interface Session {
  id: string;
  deviceName: string;
  deviceType: string;
  ipAddress: string;
  location?: string;
  lastActivity: string;
  createdAt: string;
  isCurrent: boolean;
  mfaVerified: boolean;
  biometricVerified: boolean;
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

  // Biometric Authentication
  async loginWithBiometric(data: BiometricLoginData): Promise<ApiResponse<{
    user?: User;
    token?: string;
    refreshToken?: string;
    requiresMfa?: boolean;
    sessionId?: string;
    availableMfaMethods?: string[];
  }>> {
    return apiClient.post('/biometric/authenticate/' + data.type, {
      template: data.biometricData,
      livenessProof: data.livenessProof,
    });
  }

  async getBiometricAvailability(): Promise<ApiResponse<{
    fingerprint: { available: boolean; enrolled: boolean };
    faceId: { available: boolean; enrolled: boolean };
    voicePrint: { available: boolean; enrolled: boolean };
  }>> {
    return apiClient.get('/biometric/availability');
  }

  async getBiometricEnrollments(): Promise<ApiResponse<Array<{
    type: string;
    status: string;
    lastUsed?: string;
    deviceId?: string;
  }>>> {
    return apiClient.get('/biometric/enrollments');
  }

  async enrollBiometric(data: BiometricEnrollment): Promise<ApiResponse<{
    enrollmentId: string;
    backupCodes: string[];
  }>> {
    return apiClient.post('/biometric/enroll/' + data.type, data);
  }

  async disableBiometric(type: string, password: string): Promise<ApiResponse> {
    return apiClient.delete('/biometric/enroll/' + type, { data: { password } });
  }

  async regenerateBiometricBackupCodes(type: string, password: string): Promise<ApiResponse<{
    backupCodes: string[];
  }>> {
    return apiClient.post('/biometric/regenerate-backup-codes/' + type, { password });
  }

  // MFA Verification (for login flow)
  async verifyMfa(data: MfaVerificationData): Promise<ApiResponse<{
    user: User;
    token: string;
    refreshToken: string;
  }>> {
    return apiClient.post('/mfa/verify-login', data);
  }

  async sendMfaCode(sessionId: string, method: 'sms' | 'email'): Promise<ApiResponse> {
    return apiClient.post('/mfa/send-code', { sessionId, method });
  }

  // Session Management
  async getSessions(): Promise<ApiResponse<{
    sessions: Session[];
    totalCount: number;
    currentSessionId: string;
  }>> {
    return apiClient.get('/sessions');
  }

  async getCurrentSession(): Promise<ApiResponse<Session>> {
    return apiClient.get('/sessions/current');
  }

  async invalidateSession(sessionId: string): Promise<ApiResponse> {
    return apiClient.delete('/sessions/' + sessionId);
  }

  async invalidateAllOtherSessions(): Promise<ApiResponse<{ invalidatedCount: number }>> {
    return apiClient.delete('/sessions');
  }

  async invalidateAllSessions(): Promise<ApiResponse<{ invalidatedCount: number }>> {
    return apiClient.delete('/sessions/all');
  }
}

export const authService = new AuthService();
export default authService;
