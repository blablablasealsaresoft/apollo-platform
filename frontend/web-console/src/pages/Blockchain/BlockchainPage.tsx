import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { blockchainService } from '@services/api';
import { WalletWatch, BlockchainTransaction } from '@types/index';
import { formatDate, formatRelativeTime } from '@utils/formatters';
import toast from 'react-hot-toast';
import {
  FiPlus,
  FiSearch,
  FiEye,
  FiTrash2,
  FiAlertTriangle,
  FiArrowRight,
  FiCopy,
  FiExternalLink,
  FiRefreshCw,
  FiFilter,
  FiDollarSign,
  FiActivity,
  FiClock,
  FiTag,
} from 'react-icons/fi';

type TabType = 'watchlist' | 'transactions' | 'search' | 'exchanges';

const BlockchainPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('watchlist');
  const [searchAddress, setSearchAddress] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedWallet, setSelectedWallet] = useState<WalletWatch | null>(null);
  const [newWallet, setNewWallet] = useState({
    blockchain: 'bitcoin',
    address: '',
    label: '',
    alertOnTransaction: true,
    alertThreshold: 0,
    tags: '',
  });

  const { data: watchlist, isLoading: watchlistLoading } = useQuery({
    queryKey: ['blockchain-watchlist'],
    queryFn: async () => {
      const response = await blockchainService.getWatchList();
      return response.data as WalletWatch[];
    },
  });

  const { data: transactions, isLoading: transactionsLoading } = useQuery({
    queryKey: ['blockchain-transactions'],
    queryFn: async () => {
      const response = await blockchainService.getTransactions();
      return response.data as BlockchainTransaction[];
    },
  });

  const { data: searchResults, isLoading: searchLoading, refetch: doSearch } = useQuery({
    queryKey: ['blockchain-search', searchAddress],
    queryFn: async () => {
      if (!searchAddress) return [];
      const response = await blockchainService.searchAddress(searchAddress);
      return response.data || [];
    },
    enabled: false,
  });

  const { data: exchanges } = useQuery({
    queryKey: ['blockchain-exchanges'],
    queryFn: async () => {
      const response = await blockchainService.getExchangeMonitoring();
      return response.data || [];
    },
  });

  const addWalletMutation = useMutation({
    mutationFn: async () => {
      return blockchainService.addToWatchList({
        ...newWallet,
        tags: newWallet.tags.split(',').map(t => t.trim()).filter(Boolean),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blockchain-watchlist'] });
      toast.success('Wallet added to watchlist');
      setShowAddModal(false);
      setNewWallet({ blockchain: 'bitcoin', address: '', label: '', alertOnTransaction: true, alertThreshold: 0, tags: '' });
    },
    onError: () => toast.error('Failed to add wallet'),
  });

  const removeWalletMutation = useMutation({
    mutationFn: async (id: string) => blockchainService.removeFromWatchList(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blockchain-watchlist'] });
      toast.success('Wallet removed from watchlist');
    },
    onError: () => toast.error('Failed to remove wallet'),
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const handleSearch = () => {
    if (searchAddress.trim()) {
      doSearch();
    }
  };

  const tabs = [
    { id: 'watchlist', label: 'Watchlist', icon: FiEye },
    { id: 'transactions', label: 'Transactions', icon: FiActivity },
    { id: 'search', label: 'Address Search', icon: FiSearch },
    { id: 'exchanges', label: 'Exchange Monitor', icon: FiDollarSign },
  ] as const;

  const blockchainOptions = [
    { value: 'bitcoin', label: 'Bitcoin (BTC)' },
    { value: 'ethereum', label: 'Ethereum (ETH)' },
    { value: 'litecoin', label: 'Litecoin (LTC)' },
    { value: 'monero', label: 'Monero (XMR)' },
    { value: 'tether', label: 'Tether (USDT)' },
    { value: 'binance', label: 'Binance Smart Chain' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Blockchain Tracking</h1>
          <p className="mt-1 text-sm text-gray-500">Monitor cryptocurrency wallets and trace transactions</p>
        </div>
        <button onClick={() => setShowAddModal(true)} className="btn-primary flex items-center gap-2">
          <FiPlus className="h-4 w-4" /> Add Wallet
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
              <FiEye className="h-6 w-6 text-primary-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Watched Wallets</p>
              <p className="text-2xl font-bold">{watchlist?.length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-success-100 dark:bg-success-900/30 rounded-lg">
              <FiActivity className="h-6 w-6 text-success-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Transactions Today</p>
              <p className="text-2xl font-bold">{transactions?.filter(t => new Date(t.timestamp) > new Date(Date.now() - 86400000)).length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-warning-100 dark:bg-warning-900/30 rounded-lg">
              <FiAlertTriangle className="h-6 w-6 text-warning-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Flagged Transactions</p>
              <p className="text-2xl font-bold">{transactions?.filter(t => t.flagged).length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <FiDollarSign className="h-6 w-6 text-purple-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Exchanges Monitored</p>
              <p className="text-2xl font-bold">{exchanges?.length || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 dark:border-dark-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Watchlist Tab */}
      {activeTab === 'watchlist' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Wallet Watch List</h2>
            <button onClick={() => queryClient.invalidateQueries({ queryKey: ['blockchain-watchlist'] })} className="btn-secondary btn-sm flex items-center gap-1">
              <FiRefreshCw className="h-4 w-4" /> Refresh
            </button>
          </div>
          {watchlistLoading ? (
            <div className="flex justify-center py-12"><div className="spinner" /></div>
          ) : watchlist && watchlist.length > 0 ? (
            <div className="space-y-4">
              {watchlist.map((wallet) => (
                <div key={wallet.id} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{wallet.label}</h3>
                        <span className="badge badge-primary">{wallet.blockchain}</span>
                        {wallet.alertOnTransaction && (
                          <span className="badge badge-warning">Alerts On</span>
                        )}
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <code className="text-sm bg-gray-100 dark:bg-dark-700 px-2 py-1 rounded font-mono">
                          {wallet.address.slice(0, 12)}...{wallet.address.slice(-8)}
                        </code>
                        <button onClick={() => copyToClipboard(wallet.address)} className="text-gray-400 hover:text-gray-600">
                          <FiCopy className="h-4 w-4" />
                        </button>
                        <a href={`https://blockchain.com/explorer/addresses/${wallet.blockchain}/${wallet.address}`} target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary-600">
                          <FiExternalLink className="h-4 w-4" />
                        </a>
                      </div>
                      <div className="mt-3 flex items-center gap-4 text-sm text-gray-500">
                        <span>Balance: {wallet.balance?.toFixed(4) || '0'} {wallet.blockchain === 'bitcoin' ? 'BTC' : wallet.blockchain === 'ethereum' ? 'ETH' : wallet.blockchain.toUpperCase()}</span>
                        <span>{wallet.transactionCount} transactions</span>
                        {wallet.lastActive && <span>Last active: {formatRelativeTime(wallet.lastActive)}</span>}
                      </div>
                      {wallet.tags && wallet.tags.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {wallet.tags.map((tag, i) => (
                            <span key={i} className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-dark-700 rounded">{tag}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => setSelectedWallet(wallet)} className="btn-secondary btn-sm">
                        <FiEye className="h-4 w-4" />
                      </button>
                      <button onClick={() => removeWalletMutation.mutate(wallet.id)} className="btn-secondary btn-sm text-danger-600 hover:bg-danger-50">
                        <FiTrash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <FiEye className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 text-gray-500">No wallets in your watchlist</p>
              <button onClick={() => setShowAddModal(true)} className="mt-4 btn-primary">Add Your First Wallet</button>
            </div>
          )}
        </div>
      )}

      {/* Transactions Tab */}
      {activeTab === 'transactions' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Recent Transactions</h2>
            <div className="flex items-center gap-2">
              <button className="btn-secondary btn-sm flex items-center gap-1">
                <FiFilter className="h-4 w-4" /> Filter
              </button>
              <button onClick={() => queryClient.invalidateQueries({ queryKey: ['blockchain-transactions'] })} className="btn-secondary btn-sm flex items-center gap-1">
                <FiRefreshCw className="h-4 w-4" /> Refresh
              </button>
            </div>
          </div>
          {transactionsLoading ? (
            <div className="flex justify-center py-12"><div className="spinner" /></div>
          ) : transactions && transactions.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-dark-700">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Hash</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Chain</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">From → To</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Value</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Time</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
                  {transactions.map((tx) => (
                    <tr key={tx.hash} className={`hover:bg-gray-50 dark:hover:bg-dark-700 ${tx.flagged ? 'bg-danger-50 dark:bg-danger-900/10' : ''}`}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono">{tx.hash.slice(0, 8)}...{tx.hash.slice(-6)}</code>
                          <button onClick={() => copyToClipboard(tx.hash)} className="text-gray-400 hover:text-gray-600">
                            <FiCopy className="h-3 w-3" />
                          </button>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="badge badge-gray">{tx.blockchain}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-sm">
                          <span className="font-mono">{tx.from.slice(0, 6)}...</span>
                          <FiArrowRight className="h-3 w-3 text-gray-400" />
                          <span className="font-mono">{tx.to.slice(0, 6)}...</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-semibold">{tx.value} {tx.currency}</td>
                      <td className="px-4 py-3 text-sm text-gray-500">{formatRelativeTime(tx.timestamp)}</td>
                      <td className="px-4 py-3">
                        {tx.flagged ? (
                          <div className="flex items-center gap-1">
                            <FiAlertTriangle className="h-4 w-4 text-danger-500" />
                            <span className="text-sm text-danger-600">{tx.flags?.[0] || 'Flagged'}</span>
                          </div>
                        ) : (
                          <span className="badge badge-success">{tx.confirmations}+ confirmations</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12">
              <FiActivity className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 text-gray-500">No transactions found</p>
            </div>
          )}
        </div>
      )}

      {/* Search Tab */}
      {activeTab === 'search' && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Address Search</h2>
          <div className="flex gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  value={searchAddress}
                  onChange={(e) => setSearchAddress(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="Enter wallet address or transaction hash..."
                  className="input w-full pl-10"
                />
              </div>
            </div>
            <button onClick={handleSearch} disabled={!searchAddress.trim() || searchLoading} className="btn-primary">
              {searchLoading ? 'Searching...' : 'Search'}
            </button>
          </div>
          {searchResults && searchResults.length > 0 ? (
            <div className="space-y-4">
              <h3 className="font-medium text-gray-700 dark:text-gray-300">Search Results</h3>
              {searchResults.map((result: any, i: number) => (
                <div key={i} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm">{result.address || result.hash}</p>
                      <p className="text-sm text-gray-500 mt-1">
                        {result.blockchain} | Balance: {result.balance || 0} | Transactions: {result.transactionCount || 0}
                      </p>
                    </div>
                    <button onClick={() => {
                      setNewWallet({ ...newWallet, address: result.address || result.hash, blockchain: result.blockchain });
                      setShowAddModal(true);
                    }} className="btn-secondary btn-sm">
                      Add to Watchlist
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : searchAddress && !searchLoading ? (
            <div className="text-center py-8 text-gray-500">
              No results found. Try a different address.
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              Enter an address or transaction hash to search across all blockchains.
            </div>
          )}
        </div>
      )}

      {/* Exchanges Tab */}
      {activeTab === 'exchanges' && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Exchange Monitoring</h2>
          {exchanges && exchanges.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {exchanges.map((exchange: any, i: number) => (
                <div key={i} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="h-10 w-10 rounded-full bg-gray-100 dark:bg-dark-700 flex items-center justify-center font-bold">
                      {exchange.name?.[0] || 'E'}
                    </div>
                    <div>
                      <h3 className="font-semibold">{exchange.name || 'Exchange'}</h3>
                      <p className="text-sm text-gray-500">{exchange.type || 'Centralized'}</p>
                    </div>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500">Wallets Tracked</span>
                      <span>{exchange.walletsTracked || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Suspicious Activity</span>
                      <span className={exchange.suspiciousCount > 0 ? 'text-danger-600' : ''}>
                        {exchange.suspiciousCount || 0}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Last Activity</span>
                      <span>{exchange.lastActivity ? formatRelativeTime(exchange.lastActivity) : 'N/A'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <FiDollarSign className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 text-gray-500">No exchanges being monitored</p>
            </div>
          )}
        </div>
      )}

      {/* Add Wallet Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-black/50" onClick={() => setShowAddModal(false)} />
          <div className="relative w-full max-w-md bg-white dark:bg-dark-800 rounded-lg shadow-xl">
            <div className="p-6">
              <h2 className="text-lg font-semibold mb-4">Add Wallet to Watchlist</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Blockchain</label>
                  <select
                    value={newWallet.blockchain}
                    onChange={(e) => setNewWallet({ ...newWallet, blockchain: e.target.value })}
                    className="input w-full"
                  >
                    {blockchainOptions.map((opt) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Wallet Address</label>
                  <input
                    type="text"
                    value={newWallet.address}
                    onChange={(e) => setNewWallet({ ...newWallet, address: e.target.value })}
                    placeholder="Enter wallet address"
                    className="input w-full font-mono"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Label</label>
                  <input
                    type="text"
                    value={newWallet.label}
                    onChange={(e) => setNewWallet({ ...newWallet, label: e.target.value })}
                    placeholder="e.g., Suspect A Wallet"
                    className="input w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Tags (comma separated)</label>
                  <input
                    type="text"
                    value={newWallet.tags}
                    onChange={(e) => setNewWallet({ ...newWallet, tags: e.target.value })}
                    placeholder="e.g., suspect, onecoin, high-risk"
                    className="input w-full"
                  />
                </div>
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    id="alertOnTransaction"
                    checked={newWallet.alertOnTransaction}
                    onChange={(e) => setNewWallet({ ...newWallet, alertOnTransaction: e.target.checked })}
                    className="rounded"
                  />
                  <label htmlFor="alertOnTransaction" className="text-sm">Alert on new transactions</label>
                </div>
                {newWallet.alertOnTransaction && (
                  <div>
                    <label className="block text-sm font-medium mb-2">Alert Threshold (optional)</label>
                    <input
                      type="number"
                      value={newWallet.alertThreshold}
                      onChange={(e) => setNewWallet({ ...newWallet, alertThreshold: parseFloat(e.target.value) || 0 })}
                      placeholder="0 for all transactions"
                      className="input w-full"
                    />
                    <p className="text-xs text-gray-500 mt-1">Only alert for transactions above this amount</p>
                  </div>
                )}
              </div>
              <div className="mt-6 flex justify-end gap-3">
                <button onClick={() => setShowAddModal(false)} className="btn-secondary">Cancel</button>
                <button
                  onClick={() => addWalletMutation.mutate()}
                  disabled={!newWallet.address || !newWallet.label || addWalletMutation.isPending}
                  className="btn-primary"
                >
                  {addWalletMutation.isPending ? 'Adding...' : 'Add Wallet'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlockchainPage;
