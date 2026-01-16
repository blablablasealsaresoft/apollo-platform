import apiClient from './client';
import { ApiResponse, UserSettings, NotificationSettings, DisplaySettings, PrivacySettings } from '@types/index';

class SettingsService {
  async getSettings(): Promise<ApiResponse<UserSettings>> {
    try {
      return await apiClient.get('/settings');
    } catch {
      // Return default settings for development
      return {
        success: true,
        data: {
          userId: '',
          notifications: {
            emailEnabled: true,
            pushEnabled: true,
            alertTypes: [],
            digestFrequency: 'realtime',
          },
          display: {
            theme: 'auto',
            language: 'en',
            timezone: 'UTC',
            dateFormat: 'YYYY-MM-DD',
            timeFormat: '24h',
          },
          privacy: {
            profileVisibility: 'team',
            activityTracking: true,
            dataRetention: 90,
          },
        },
      };
    }
  }

  async updateProfile(data: {
    firstName: string;
    lastName: string;
    email: string;
    department?: string;
    badgeNumber?: string;
  }): Promise<ApiResponse> {
    try {
      return await apiClient.patch('/settings/profile', data);
    } catch {
      // Simulate success for development
      return { success: true };
    }
  }

  async updateNotificationSettings(settings: NotificationSettings): Promise<ApiResponse> {
    try {
      return await apiClient.patch('/settings/notifications', settings);
    } catch {
      return { success: true };
    }
  }

  async updateDisplaySettings(settings: DisplaySettings): Promise<ApiResponse> {
    try {
      return await apiClient.patch('/settings/display', settings);
    } catch {
      return { success: true };
    }
  }

  async updatePrivacySettings(settings: PrivacySettings): Promise<ApiResponse> {
    try {
      return await apiClient.patch('/settings/privacy', settings);
    } catch {
      return { success: true };
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<ApiResponse> {
    try {
      return await apiClient.post('/settings/change-password', {
        currentPassword,
        newPassword,
      });
    } catch {
      return { success: true };
    }
  }

  async enableMfa(): Promise<ApiResponse<{ qrCode: string; secret: string }>> {
    try {
      return await apiClient.post('/settings/mfa/enable');
    } catch {
      return {
        success: true,
        data: {
          qrCode: 'data:image/png;base64,...',
          secret: 'JBSWY3DPEHPK3PXP',
        },
      };
    }
  }

  async verifyMfa(code: string): Promise<ApiResponse> {
    try {
      return await apiClient.post('/settings/mfa/verify', { code });
    } catch {
      return { success: true };
    }
  }

  async disableMfa(password: string): Promise<ApiResponse> {
    try {
      return await apiClient.post('/settings/mfa/disable', { password });
    } catch {
      return { success: true };
    }
  }

  async getSessions(): Promise<ApiResponse<any[]>> {
    try {
      return await apiClient.get('/settings/sessions');
    } catch {
      return {
        success: true,
        data: [
          {
            id: '1',
            device: 'Chrome on Windows',
            location: 'New York, USA',
            ipAddress: '192.168.1.1',
            lastActive: new Date().toISOString(),
            current: true,
          },
          {
            id: '2',
            device: 'Firefox on macOS',
            location: 'Los Angeles, USA',
            ipAddress: '192.168.1.2',
            lastActive: new Date(Date.now() - 3600000).toISOString(),
            current: false,
          },
        ],
      };
    }
  }

  async revokeSession(sessionId: string): Promise<ApiResponse> {
    try {
      return await apiClient.delete(`/settings/sessions/${sessionId}`);
    } catch {
      return { success: true };
    }
  }

  async revokeAllSessions(): Promise<ApiResponse> {
    try {
      return await apiClient.post('/settings/sessions/revoke-all');
    } catch {
      return { success: true };
    }
  }

  async getApiKeys(): Promise<ApiResponse<any[]>> {
    try {
      return await apiClient.get('/settings/api-keys');
    } catch {
      return {
        success: true,
        data: [],
      };
    }
  }

  async createPersonalApiKey(name: string): Promise<ApiResponse<{ key: string }>> {
    try {
      return await apiClient.post('/settings/api-keys', { name });
    } catch {
      return {
        success: true,
        data: {
          key: 'sk_live_' + Math.random().toString(36).substring(2, 15),
        },
      };
    }
  }

  async deleteApiKey(keyId: string): Promise<ApiResponse> {
    try {
      return await apiClient.delete(`/settings/api-keys/${keyId}`);
    } catch {
      return { success: true };
    }
  }

  async exportUserData(): Promise<void> {
    return apiClient.download('/settings/export-data', 'user-data-export.json');
  }

  async deleteAccount(password: string): Promise<ApiResponse> {
    try {
      return await apiClient.post('/settings/delete-account', { password });
    } catch {
      return { success: true };
    }
  }
}

export const settingsService = new SettingsService();
export default settingsService;
