/**
 * API Caller - Handles actual HTTP requests to APIs
 * Manages authentication, rate limiting, retries, and error handling
 *
 * @module APICaller
 * @elite-engineering
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { RateLimiter } from './rate-limiter';
import { ErrorHandler } from './error-handler';

interface API {
  id: string;
  name: string;
  url: string;
  auth: string;
  free: boolean | string;
  rate_limit: string;
  endpoints: any[];
}

interface CallOptions {
  endpoint?: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  params?: any;
  data?: any;
  headers?: any;
  timeout?: number;
  retries?: number;
}

/**
 * Programmatic API caller with enterprise-grade reliability
 */
export class APICaller {
  private rateLimiter: RateLimiter;
  private errorHandler: ErrorHandler;
  private axiosInstances: Map<string, AxiosInstance>;
  private apiKeys: Map<string, string>;

  constructor() {
    this.rateLimiter = new RateLimiter();
    this.errorHandler = new ErrorHandler();
    this.axiosInstances = new Map();
    this.apiKeys = new Map();
    this.loadAPIKeys();
  }

  /**
   * Load API keys from environment
   */
  private loadAPIKeys(): void {
    // Load from environment variables or secure key store
    this.apiKeys.set('ipstack', process.env.IPSTACK_API_KEY || '');
    this.apiKeys.set('etherscan', process.env.ETHERSCAN_API_KEY || '');
    this.apiKeys.set('alpha_vantage', process.env.ALPHA_VANTAGE_API_KEY || '');
    // ... load all API keys
  }

  /**
   * Get or create Axios instance for API
   */
  private getAxiosInstance(api: API): AxiosInstance {
    if (!this.axiosInstances.has(api.id)) {
      const instance = axios.create({
        baseURL: api.url,
        timeout: 30000,
        headers: {
          'User-Agent': 'Apollo-Platform/1.0',
          'Accept': 'application/json'
        }
      });

      // Add request interceptor for authentication
      instance.interceptors.request.use((config) => {
        return this.addAuthentication(config, api);
      });

      // Add response interceptor for error handling
      instance.interceptors.response.use(
        response => response,
        error => this.errorHandler.handleAxiosError(error, api)
      );

      this.axiosInstances.set(api.id, instance);
    }

    return this.axiosInstances.get(api.id)!;
  }

  /**
   * Add authentication to request
   */
  private addAuthentication(config: AxiosRequestConfig, api: API): AxiosRequestConfig {
    const apiKey = this.apiKeys.get(api.id);

    switch (api.auth) {
      case 'apiKey':
        // Common API key patterns
        if (api.id === 'ipstack') {
          config.params = { ...config.params, access_key: apiKey };
        } else if (api.id === 'etherscan') {
          config.params = { ...config.params, apikey: apiKey };
        } else {
          config.params = { ...config.params, api_key: apiKey };
        }
        break;

      case 'bearer':
      case 'token':
        config.headers = {
          ...config.headers,
          'Authorization': `Bearer ${apiKey}`
        };
        break;

      case 'oauth2':
        // OAuth2 token management
        config.headers = {
          ...config.headers,
          'Authorization': `Bearer ${apiKey}`
        };
        break;

      case 'basic':
        config.auth = {
          username: apiKey,
          password: ''
        };
        break;

      case 'none':
      default:
        // No authentication required
        break;
    }

    return config;
  }

  /**
   * Call any API from the registry
   *
   * @param api - API configuration
   * @param options - Call options
   * @returns API response data
   */
  async call(api: API, options: CallOptions = {}): Promise<any> {
    // Wait for rate limit slot
    await this.rateLimiter.waitForSlot(api.id);

    const instance = this.getAxiosInstance(api);
    const retries = options.retries || 3;

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const config: AxiosRequestConfig = {
          method: options.method || 'GET',
          url: options.endpoint || '',
          params: options.params,
          data: options.data,
          headers: options.headers,
          timeout: options.timeout || 30000
        };

        const response = await instance.request(config);
        return response.data;

      } catch (error) {
        if (attempt === retries) {
          throw error;
        }

        // Exponential backoff
        const delay = Math.pow(2, attempt) * 1000;
        await this.sleep(delay);
      }
    }
  }

  /**
   * Batch call multiple APIs in parallel
   */
  async batchCall(
    apis: API[],
    options: CallOptions = {}
  ): Promise<Array<{ api: string; success: boolean; data?: any; error?: string }>> {
    const promises = apis.map(async (api) => {
      try {
        const data = await this.call(api, options);
        return { api: api.id, success: true, data };
      } catch (error) {
        return { api: api.id, success: false, error: error.message };
      }
    });

    const results = await Promise.allSettled(promises);
    return results.map(r => r.status === 'fulfilled' ? r.value : r.reason);
  }

  /**
   * Stream data from API (for long-running calls)
   */
  async stream(api: API, options: CallOptions, callback: (chunk: any) => void): Promise<void> {
    await this.rateLimiter.waitForSlot(api.id);

    const instance = this.getAxiosInstance(api);
    const response = await instance.request({
      ...options,
      responseType: 'stream'
    });

    response.data.on('data', (chunk: any) => {
      callback(chunk);
    });

    return new Promise((resolve, reject) => {
      response.data.on('end', resolve);
      response.data.on('error', reject);
    });
  }

  /**
   * Helper: Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get API call statistics
   */
  getStatistics(apiId: string): {
    totalCalls: number;
    successfulCalls: number;
    failedCalls: number;
    avgResponseTime: number;
  } {
    // Return statistics tracked by rate limiter
    return this.rateLimiter.getStatistics(apiId);
  }
}

export const apiCaller = new APICaller();
