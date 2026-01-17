import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import { ApiResponse, ApiError } from '@types/index';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';

// Standardized error codes for frontend
export const API_ERROR_CODES = {
  // Network errors
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  CONNECTION_REFUSED: 'CONNECTION_REFUSED',

  // Authentication errors
  UNAUTHORIZED: 'UNAUTHORIZED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_REFRESH_FAILED: 'TOKEN_REFRESH_FAILED',

  // Client errors
  BAD_REQUEST: 'BAD_REQUEST',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  FORBIDDEN: 'FORBIDDEN',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',

  // Server errors
  SERVER_ERROR: 'SERVER_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',

  // Generic
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
} as const;

// User-friendly error messages
const ERROR_MESSAGES: Record<string, string> = {
  [API_ERROR_CODES.NETWORK_ERROR]: 'Unable to connect to the server. Please check your internet connection.',
  [API_ERROR_CODES.TIMEOUT]: 'The request took too long to complete. Please try again.',
  [API_ERROR_CODES.CONNECTION_REFUSED]: 'The server is not responding. Please try again later.',
  [API_ERROR_CODES.UNAUTHORIZED]: 'Please log in to continue.',
  [API_ERROR_CODES.SESSION_EXPIRED]: 'Your session has expired. Please log in again.',
  [API_ERROR_CODES.INVALID_TOKEN]: 'Authentication failed. Please log in again.',
  [API_ERROR_CODES.TOKEN_REFRESH_FAILED]: 'Unable to refresh your session. Please log in again.',
  [API_ERROR_CODES.BAD_REQUEST]: 'The request was invalid. Please check your input.',
  [API_ERROR_CODES.VALIDATION_ERROR]: 'Please check the form for errors.',
  [API_ERROR_CODES.NOT_FOUND]: 'The requested resource was not found.',
  [API_ERROR_CODES.FORBIDDEN]: 'You do not have permission to perform this action.',
  [API_ERROR_CODES.CONFLICT]: 'This action conflicts with existing data.',
  [API_ERROR_CODES.RATE_LIMITED]: 'Too many requests. Please wait a moment and try again.',
  [API_ERROR_CODES.SERVER_ERROR]: 'An unexpected server error occurred. Please try again later.',
  [API_ERROR_CODES.SERVICE_UNAVAILABLE]: 'The service is temporarily unavailable. Please try again later.',
  [API_ERROR_CODES.UNKNOWN_ERROR]: 'An unexpected error occurred. Please try again.',
};

class ApiClient {
  private client: AxiosInstance;
  private refreshTokenPromise: Promise<string> | null = null;
  private maxRetries = 2;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const token = localStorage.getItem('apollo_token');
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        // Add request ID for tracking
        config.headers['X-Request-ID'] = this.generateRequestId();
        return config;
      },
      (error: AxiosError) => {
        console.error('[API] Request setup error:', error.message);
        return Promise.reject(this.createError(API_ERROR_CODES.UNKNOWN_ERROR, error.message));
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & {
          _retry?: boolean;
          _retryCount?: number;
        };

        // Handle 401 errors (unauthorized)
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const newToken = await this.refreshAccessToken();
            if (newToken && originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return this.client(originalRequest);
            }
          } catch (refreshError) {
            // Refresh failed, logout user
            this.handleAuthenticationError();
            return Promise.reject(this.createError(
              API_ERROR_CODES.TOKEN_REFRESH_FAILED,
              'Session refresh failed'
            ));
          }
        }

        // Handle rate limiting with automatic retry
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'];
          const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 5000;

          if (!originalRequest._retryCount || originalRequest._retryCount < this.maxRetries) {
            originalRequest._retryCount = (originalRequest._retryCount || 0) + 1;
            await this.delay(waitTime);
            return this.client(originalRequest);
          }
        }

        return Promise.reject(this.handleError(error));
      }
    );
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async refreshAccessToken(): Promise<string> {
    // Prevent multiple simultaneous refresh requests
    if (this.refreshTokenPromise) {
      return this.refreshTokenPromise;
    }

    this.refreshTokenPromise = (async () => {
      try {
        const refreshToken = localStorage.getItem('apollo_refresh_token');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
          refreshToken,
        });

        const { token } = response.data.data;
        localStorage.setItem('apollo_token', token);
        return token;
      } finally {
        this.refreshTokenPromise = null;
      }
    })();

    return this.refreshTokenPromise;
  }

  private handleAuthenticationError() {
    localStorage.removeItem('apollo_token');
    localStorage.removeItem('apollo_refresh_token');
    localStorage.removeItem('apollo_user');
    // Use history API to avoid full page reload when possible
    if (window.location.pathname !== '/login') {
      window.location.href = '/login?reason=session_expired';
    }
  }

  private createError(code: string, message?: string, details?: any): ApiError {
    return {
      code,
      message: message || ERROR_MESSAGES[code] || ERROR_MESSAGES[API_ERROR_CODES.UNKNOWN_ERROR],
      details,
    };
  }

  private handleError(error: AxiosError): ApiError {
    // Log error for debugging (will be stripped in production builds if needed)
    console.error('[API Error]', {
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      message: error.message,
    });

    if (error.response) {
      // Server responded with error
      const status = error.response.status;
      const data: any = error.response.data;

      // Map HTTP status codes to error codes
      let errorCode: string;
      switch (status) {
        case 400:
          errorCode = data.code?.includes('VALIDATION') ? API_ERROR_CODES.VALIDATION_ERROR : API_ERROR_CODES.BAD_REQUEST;
          break;
        case 401:
          errorCode = API_ERROR_CODES.UNAUTHORIZED;
          break;
        case 403:
          errorCode = API_ERROR_CODES.FORBIDDEN;
          break;
        case 404:
          errorCode = API_ERROR_CODES.NOT_FOUND;
          break;
        case 409:
          errorCode = API_ERROR_CODES.CONFLICT;
          break;
        case 429:
          errorCode = API_ERROR_CODES.RATE_LIMITED;
          break;
        case 500:
          errorCode = API_ERROR_CODES.SERVER_ERROR;
          break;
        case 502:
        case 503:
        case 504:
          errorCode = API_ERROR_CODES.SERVICE_UNAVAILABLE;
          break;
        default:
          errorCode = status >= 500 ? API_ERROR_CODES.SERVER_ERROR : API_ERROR_CODES.BAD_REQUEST;
      }

      return this.createError(
        data.code || errorCode,
        data.message || data.error?.message || ERROR_MESSAGES[errorCode],
        data.details || data.error?.details
      );
    } else if (error.request) {
      // Request made but no response
      if (error.code === 'ECONNABORTED') {
        return this.createError(API_ERROR_CODES.TIMEOUT);
      }
      if (error.code === 'ERR_NETWORK') {
        return this.createError(API_ERROR_CODES.CONNECTION_REFUSED);
      }
      return this.createError(API_ERROR_CODES.NETWORK_ERROR);
    } else {
      // Error setting up request
      return this.createError(API_ERROR_CODES.UNKNOWN_ERROR, error.message);
    }
  }

  // HTTP Methods
  async get<T = any>(url: string, params?: any): Promise<ApiResponse<T>> {
    const response = await this.client.get(url, { params });
    return response.data;
  }

  async post<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    const response = await this.client.post(url, data);
    return response.data;
  }

  async put<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    const response = await this.client.put(url, data);
    return response.data;
  }

  async patch<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    const response = await this.client.patch(url, data);
    return response.data;
  }

  async delete<T = any>(url: string): Promise<ApiResponse<T>> {
    const response = await this.client.delete(url);
    return response.data;
  }

  async upload<T = any>(url: string, formData: FormData): Promise<ApiResponse<T>> {
    const response = await this.client.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  async download(url: string, filename: string): Promise<void> {
    const response = await this.client.get(url, {
      responseType: 'blob',
    });

    const blob = new Blob([response.data]);
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    window.URL.revokeObjectURL(link.href);
  }
}

export const apiClient = new ApiClient();
export default apiClient;
