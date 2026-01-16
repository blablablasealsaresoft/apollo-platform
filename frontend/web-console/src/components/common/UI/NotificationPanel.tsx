/**
 * Apollo Platform - Real-Time Notification Panel
 * Displays live alerts, surveillance matches, and system notifications
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  FiBell,
  FiX,
  FiCheck,
  FiCheckCircle,
  FiAlertCircle,
  FiAlertTriangle,
  FiInfo,
  FiUser,
  FiLink,
  FiEye,
  FiActivity,
  FiExternalLink,
  FiTrash2,
} from 'react-icons/fi';
import { useAlerts, useNotifications, useSurveillance, useBlockchain } from '@hooks/useWebSocket';
import { cn } from '@utils/cn';
import { formatDistanceToNow } from 'date-fns';

interface NotificationPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'alerts' | 'surveillance' | 'blockchain' | 'notifications';

const NotificationPanel: React.FC<NotificationPanelProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<TabType>('alerts');
  const [filter, setFilter] = useState<'all' | 'critical' | 'unread'>('all');

  // Real-time data hooks
  const { alerts, acknowledgeAlert, clearAlerts, unreadCount, criticalCount } = useAlerts();
  const { notifications, markAsRead, markAllAsRead, clearNotifications, unreadCount: notifUnread } = useNotifications();
  const { matches: surveillanceMatches, highConfidenceMatches, clearMatches, isLive } = useSurveillance();
  const { transactions, flaggedTransactions, clearTransactions, isMonitoring } = useBlockchain();

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <FiAlertCircle className="h-5 w-5 text-danger-500" />;
      case 'error':
        return <FiAlertCircle className="h-5 w-5 text-danger-400" />;
      case 'warning':
        return <FiAlertTriangle className="h-5 w-5 text-warning-500" />;
      default:
        return <FiInfo className="h-5 w-5 text-primary-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const classes = {
      critical: 'bg-danger-500/20 text-danger-500 border-danger-500/30',
      error: 'bg-danger-400/20 text-danger-400 border-danger-400/30',
      warning: 'bg-warning-500/20 text-warning-500 border-warning-500/30',
      info: 'bg-primary-500/20 text-primary-500 border-primary-500/30',
    };
    return classes[severity as keyof typeof classes] || classes.info;
  };

  const formatTime = (timestamp: string) => {
    try {
      return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
    } catch {
      return 'Unknown time';
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    if (filter === 'critical') return alert.severity === 'critical';
    if (filter === 'unread') return alert.status === 'new';
    return true;
  });

  const tabs = [
    { id: 'alerts' as TabType, label: 'Alerts', count: unreadCount, critical: criticalCount },
    { id: 'surveillance' as TabType, label: 'Surveillance', count: highConfidenceMatches.length, live: isLive },
    { id: 'blockchain' as TabType, label: 'Blockchain', count: flaggedTransactions.length, live: isMonitoring },
    { id: 'notifications' as TabType, label: 'Messages', count: notifUnread },
  ];

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-96 flex-col bg-dark-800 shadow-xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-dark-700 px-4 py-3">
        <div className="flex items-center gap-2">
          <FiBell className="h-5 w-5 text-primary-400" />
          <h2 className="text-lg font-semibold text-white">Notifications</h2>
          {criticalCount > 0 && (
            <span className="ml-2 animate-pulse rounded-full bg-danger-500 px-2 py-0.5 text-xs font-bold text-white">
              {criticalCount} CRITICAL
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="rounded-md p-1 text-gray-400 hover:bg-dark-700 hover:text-white"
        >
          <FiX className="h-5 w-5" />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-dark-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'relative flex-1 px-3 py-2 text-sm font-medium transition-colors',
              activeTab === tab.id
                ? 'bg-dark-700 text-white'
                : 'text-gray-400 hover:bg-dark-700/50 hover:text-white'
            )}
          >
            <span className="flex items-center justify-center gap-1">
              {tab.label}
              {tab.count > 0 && (
                <span
                  className={cn(
                    'ml-1 rounded-full px-1.5 py-0.5 text-xs',
                    tab.critical && tab.critical > 0
                      ? 'bg-danger-500 text-white animate-pulse'
                      : 'bg-primary-500/20 text-primary-400'
                  )}
                >
                  {tab.count}
                </span>
              )}
              {tab.live && (
                <span className="ml-1 h-2 w-2 animate-pulse rounded-full bg-success-500" />
              )}
            </span>
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div className="space-y-1 p-2">
            {/* Filter */}
            <div className="flex gap-2 border-b border-dark-700 pb-2 mb-2">
              {(['all', 'critical', 'unread'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={cn(
                    'rounded px-2 py-1 text-xs',
                    filter === f
                      ? 'bg-primary-500 text-white'
                      : 'bg-dark-700 text-gray-400 hover:text-white'
                  )}
                >
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
              <button
                onClick={clearAlerts}
                className="ml-auto rounded px-2 py-1 text-xs bg-dark-700 text-gray-400 hover:text-danger-400"
              >
                Clear All
              </button>
            </div>

            {filteredAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                <FiCheckCircle className="h-8 w-8 mb-2" />
                <p>No alerts to display</p>
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className={cn(
                    'rounded-lg border p-3 transition-colors',
                    alert.status === 'new'
                      ? 'border-dark-600 bg-dark-700/50'
                      : 'border-dark-700 bg-dark-800',
                    alert.severity === 'critical' && alert.status === 'new' && 'border-danger-500/50 animate-pulse'
                  )}
                >
                  <div className="flex items-start gap-3">
                    {getSeverityIcon(alert.severity)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            'rounded-full border px-2 py-0.5 text-xs font-medium',
                            getSeverityBadge(alert.severity)
                          )}
                        >
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500">
                          {formatTime(alert.createdAt)}
                        </span>
                      </div>
                      <h4 className="mt-1 font-medium text-white truncate">{alert.title}</h4>
                      <p className="mt-1 text-sm text-gray-400 line-clamp-2">{alert.message}</p>
                      {alert.relatedEntity && (
                        <div className="mt-2 flex items-center gap-1 text-xs text-primary-400">
                          <FiLink className="h-3 w-3" />
                          <span>{alert.relatedEntity.type}: {alert.relatedEntity.name || alert.relatedEntity.id}</span>
                        </div>
                      )}
                      {alert.status === 'new' && (
                        <button
                          onClick={() => acknowledgeAlert(alert.id)}
                          className="mt-2 flex items-center gap-1 rounded bg-primary-500/20 px-2 py-1 text-xs text-primary-400 hover:bg-primary-500/30"
                        >
                          <FiCheck className="h-3 w-3" />
                          Acknowledge
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Surveillance Tab */}
        {activeTab === 'surveillance' && (
          <div className="space-y-1 p-2">
            <div className="flex items-center justify-between border-b border-dark-700 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-400">Live Feed</span>
                {isLive && <span className="h-2 w-2 animate-pulse rounded-full bg-success-500" />}
              </div>
              <button
                onClick={clearMatches}
                className="rounded px-2 py-1 text-xs bg-dark-700 text-gray-400 hover:text-danger-400"
              >
                Clear
              </button>
            </div>

            {surveillanceMatches.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                <FiEye className="h-8 w-8 mb-2" />
                <p>No surveillance matches</p>
              </div>
            ) : (
              surveillanceMatches.map((match) => (
                <div
                  key={match.matchId}
                  className={cn(
                    'rounded-lg border border-dark-600 bg-dark-700/50 p-3',
                    match.confidence >= 0.95 && 'border-danger-500/50'
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-danger-500/20">
                      <FiUser className="h-5 w-5 text-danger-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium text-white">{match.targetName}</h4>
                        <span
                          className={cn(
                            'rounded px-2 py-0.5 text-xs font-bold',
                            match.confidence >= 0.95
                              ? 'bg-danger-500/20 text-danger-400'
                              : match.confidence >= 0.85
                              ? 'bg-warning-500/20 text-warning-400'
                              : 'bg-primary-500/20 text-primary-400'
                          )}
                        >
                          {(match.confidence * 100).toFixed(1)}%
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-gray-400">{match.sourceName}</p>
                      {match.location?.address && (
                        <p className="mt-1 text-xs text-gray-500">{match.location.address}</p>
                      )}
                      <p className="mt-1 text-xs text-gray-500">{formatTime(match.timestamp)}</p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Blockchain Tab */}
        {activeTab === 'blockchain' && (
          <div className="space-y-1 p-2">
            <div className="flex items-center justify-between border-b border-dark-700 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-400">Transaction Monitor</span>
                {isMonitoring && <span className="h-2 w-2 animate-pulse rounded-full bg-success-500" />}
              </div>
              <button
                onClick={clearTransactions}
                className="rounded px-2 py-1 text-xs bg-dark-700 text-gray-400 hover:text-danger-400"
              >
                Clear
              </button>
            </div>

            {transactions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                <FiActivity className="h-8 w-8 mb-2" />
                <p>No transactions detected</p>
              </div>
            ) : (
              transactions.slice(0, 20).map((tx, index) => (
                <div
                  key={tx.transactionHash || index}
                  className={cn(
                    'rounded-lg border border-dark-600 bg-dark-700/50 p-3',
                    tx.riskScore >= 70 && 'border-warning-500/50',
                    tx.riskScore >= 90 && 'border-danger-500/50'
                  )}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-dark-600 px-2 py-0.5 text-xs text-gray-300 uppercase">
                          {tx.blockchain}
                        </span>
                        {tx.riskScore >= 70 && (
                          <span
                            className={cn(
                              'rounded px-2 py-0.5 text-xs font-bold',
                              tx.riskScore >= 90
                                ? 'bg-danger-500/20 text-danger-400'
                                : 'bg-warning-500/20 text-warning-400'
                            )}
                          >
                            Risk: {tx.riskScore}
                          </span>
                        )}
                        {tx.mixerDetected && (
                          <span className="rounded bg-danger-500/20 px-2 py-0.5 text-xs text-danger-400">
                            MIXER
                          </span>
                        )}
                      </div>
                      <p className="mt-1 font-mono text-sm text-white">
                        {tx.value.toFixed(6)} {tx.currency}
                      </p>
                      {tx.usdValue && (
                        <p className="text-xs text-gray-400">${tx.usdValue.toLocaleString()}</p>
                      )}
                      <p className="mt-1 font-mono text-xs text-gray-500 truncate">
                        {tx.transactionHash}
                      </p>
                      <p className="text-xs text-gray-500">{formatTime(tx.timestamp)}</p>
                    </div>
                    <a
                      href={`https://etherscan.io/tx/${tx.transactionHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-primary-400"
                    >
                      <FiExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Notifications Tab */}
        {activeTab === 'notifications' && (
          <div className="space-y-1 p-2">
            <div className="flex items-center justify-between border-b border-dark-700 pb-2 mb-2">
              <span className="text-sm text-gray-400">{notifUnread} unread</span>
              <div className="flex gap-2">
                <button
                  onClick={markAllAsRead}
                  className="rounded px-2 py-1 text-xs bg-dark-700 text-gray-400 hover:text-white"
                >
                  Mark All Read
                </button>
                <button
                  onClick={clearNotifications}
                  className="rounded px-2 py-1 text-xs bg-dark-700 text-gray-400 hover:text-danger-400"
                >
                  Clear
                </button>
              </div>
            </div>

            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-gray-500">
                <FiBell className="h-8 w-8 mb-2" />
                <p>No notifications</p>
              </div>
            ) : (
              notifications.map((notif) => (
                <div
                  key={notif.id}
                  className={cn(
                    'rounded-lg border p-3 transition-colors cursor-pointer hover:bg-dark-700',
                    notif.read
                      ? 'border-dark-700 bg-dark-800'
                      : 'border-dark-600 bg-dark-700/50'
                  )}
                  onClick={() => markAsRead(notif.id)}
                >
                  <div className="flex items-start gap-3">
                    {!notif.read && (
                      <span className="mt-1.5 h-2 w-2 flex-shrink-0 rounded-full bg-primary-500" />
                    )}
                    <div className="flex-1 min-w-0">
                      <h4 className="font-medium text-white">{notif.title}</h4>
                      <p className="mt-1 text-sm text-gray-400 line-clamp-2">{notif.message}</p>
                      <p className="mt-1 text-xs text-gray-500">{formatTime(notif.createdAt)}</p>
                    </div>
                    {notif.actionUrl && (
                      <a
                        href={notif.actionUrl}
                        className="text-primary-400 hover:text-primary-300"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <FiExternalLink className="h-4 w-4" />
                      </a>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default NotificationPanel;
