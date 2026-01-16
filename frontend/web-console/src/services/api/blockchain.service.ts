import apiClient from './client';
import { BlockchainTransaction, WalletWatch, ApiResponse, FilterOptions, PaginationOptions } from '@types/index';

export interface CreateWalletWatchData {
  blockchain: string;
  address: string;
  label: string;
  targetId?: string;
  alertOnTransaction: boolean;
  alertThreshold?: number;
  tags?: string[];
}

class BlockchainService {
  async getTransactions(
    filters?: FilterOptions,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<BlockchainTransaction[]>> {
    return apiClient.get('/blockchain/transactions', { ...filters, ...pagination });
  }

  async getTransactionById(blockchain: string, hash: string): Promise<ApiResponse<BlockchainTransaction>> {
    return apiClient.get(`/blockchain/${blockchain}/transactions/${hash}`);
  }

  async getWalletBalance(blockchain: string, address: string): Promise<ApiResponse<{ balance: number; currency: string }>> {
    return apiClient.get(`/blockchain/${blockchain}/wallets/${address}/balance`);
  }

  async getWalletTransactions(
    blockchain: string,
    address: string,
    pagination?: PaginationOptions
  ): Promise<ApiResponse<BlockchainTransaction[]>> {
    return apiClient.get(`/blockchain/${blockchain}/wallets/${address}/transactions`, pagination);
  }

  async traceTransaction(blockchain: string, hash: string, depth: number = 3): Promise<ApiResponse<any>> {
    return apiClient.get(`/blockchain/${blockchain}/transactions/${hash}/trace`, { depth });
  }

  async getWatchList(): Promise<ApiResponse<WalletWatch[]>> {
    return apiClient.get('/blockchain/watchlist');
  }

  async addToWatchList(data: CreateWalletWatchData): Promise<ApiResponse<WalletWatch>> {
    return apiClient.post('/blockchain/watchlist', data);
  }

  async removeFromWatchList(id: string): Promise<ApiResponse> {
    return apiClient.delete(`/blockchain/watchlist/${id}`);
  }

  async updateWatchListItem(id: string, data: Partial<CreateWalletWatchData>): Promise<ApiResponse<WalletWatch>> {
    return apiClient.patch(`/blockchain/watchlist/${id}`, data);
  }

  async getAddressClusters(blockchain: string, address: string): Promise<ApiResponse<any>> {
    return apiClient.get(`/blockchain/${blockchain}/wallets/${address}/clusters`);
  }

  async getExchangeMonitoring(): Promise<ApiResponse<any[]>> {
    return apiClient.get('/blockchain/exchanges/monitoring');
  }

  async searchAddress(address: string): Promise<ApiResponse<any[]>> {
    return apiClient.get('/blockchain/search', { address });
  }
}

export const blockchainService = new BlockchainService();
export default blockchainService;
