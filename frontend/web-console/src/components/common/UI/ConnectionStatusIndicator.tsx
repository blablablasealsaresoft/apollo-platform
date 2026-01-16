/**
 * Apollo Platform - Connection Status Indicator
 * Real-time WebSocket connection status display component
 */

import React, { useState, useEffect } from 'react';
import { FiWifi, FiWifiOff, FiRefreshCw, FiAlertCircle, FiCheck } from 'react-icons/fi';
import { useConnectionStatus } from '@hooks/useWebSocket';
import { ConnectionState } from '@services/websocket/types';
import { cn } from '@utils/cn';

interface ConnectionStatusIndicatorProps {
  showLatency?: boolean;
  showText?: boolean;
  compact?: boolean;
  className?: string;
}

const ConnectionStatusIndicator: React.FC<ConnectionStatusIndicatorProps> = ({
  showLatency = true,
  showText = true,
  compact = false,
  className,
}) => {
  const { state, latency, reconnectAttempts, statusText, statusColor, isOnline } = useConnectionStatus();
  const [showTooltip, setShowTooltip] = useState(false);
  const [pulse, setPulse] = useState(false);

  // Pulse animation on state change
  useEffect(() => {
    setPulse(true);
    const timer = setTimeout(() => setPulse(false), 1000);
    return () => clearTimeout(timer);
  }, [state]);

  const getIcon = () => {
    switch (state) {
      case ConnectionState.CONNECTED:
      case ConnectionState.AUTHENTICATED:
        return <FiWifi className="h-4 w-4" />;
      case ConnectionState.CONNECTING:
      case ConnectionState.RECONNECTING:
        return <FiRefreshCw className="h-4 w-4 animate-spin" />;
      case ConnectionState.FAILED:
        return <FiAlertCircle className="h-4 w-4" />;
      default:
        return <FiWifiOff className="h-4 w-4" />;
    }
  };

  const getColorClasses = () => {
    switch (statusColor) {
      case 'green':
        return 'text-success-500 bg-success-500/10';
      case 'blue':
        return 'text-primary-500 bg-primary-500/10';
      case 'yellow':
        return 'text-warning-500 bg-warning-500/10';
      case 'orange':
        return 'text-warning-600 bg-warning-600/10';
      case 'red':
        return 'text-danger-500 bg-danger-500/10';
      default:
        return 'text-gray-400 bg-gray-400/10';
    }
  };

  const getDotColorClasses = () => {
    switch (statusColor) {
      case 'green':
        return 'bg-success-500';
      case 'blue':
        return 'bg-primary-500';
      case 'yellow':
        return 'bg-warning-500';
      case 'orange':
        return 'bg-warning-600';
      case 'red':
        return 'bg-danger-500';
      default:
        return 'bg-gray-400';
    }
  };

  const getLatencyColor = () => {
    if (!latency) return 'text-gray-400';
    if (latency < 100) return 'text-success-500';
    if (latency < 300) return 'text-warning-500';
    return 'text-danger-500';
  };

  if (compact) {
    return (
      <div
        className={cn(
          'relative flex items-center',
          className
        )}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
      >
        <span
          className={cn(
            'h-2 w-2 rounded-full transition-all duration-300',
            getDotColorClasses(),
            pulse && 'scale-125',
            isOnline && 'animate-pulse'
          )}
        />

        {/* Tooltip */}
        {showTooltip && (
          <div className="absolute bottom-full left-1/2 mb-2 -translate-x-1/2 whitespace-nowrap rounded-md bg-dark-800 px-3 py-2 text-xs text-white shadow-lg">
            <div className="flex items-center gap-2">
              {getIcon()}
              <span>{statusText}</span>
            </div>
            {latency && isOnline && (
              <div className={cn('mt-1', getLatencyColor())}>
                Latency: {latency}ms
              </div>
            )}
            <div className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-dark-800" />
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm transition-all duration-300',
        getColorClasses(),
        pulse && 'ring-2 ring-offset-2',
        className
      )}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      {/* Status Dot */}
      <span
        className={cn(
          'h-2 w-2 rounded-full transition-all duration-300',
          getDotColorClasses(),
          isOnline && 'animate-pulse'
        )}
      />

      {/* Icon */}
      {getIcon()}

      {/* Status Text */}
      {showText && (
        <span className="font-medium">{statusText}</span>
      )}

      {/* Latency */}
      {showLatency && latency && isOnline && (
        <span className={cn('text-xs', getLatencyColor())}>
          {latency}ms
        </span>
      )}

      {/* Reconnect attempts */}
      {state === ConnectionState.RECONNECTING && reconnectAttempts > 0 && (
        <span className="text-xs text-gray-500">
          ({reconnectAttempts})
        </span>
      )}
    </div>
  );
};

/**
 * Minimal connection status indicator for header/navbar
 */
export const ConnectionStatusDot: React.FC<{ className?: string }> = ({ className }) => {
  const { isOnline, state, latency } = useConnectionStatus();
  const [showTooltip, setShowTooltip] = useState(false);

  const getDotColor = () => {
    switch (state) {
      case ConnectionState.AUTHENTICATED:
        return 'bg-success-500';
      case ConnectionState.CONNECTED:
        return 'bg-primary-500';
      case ConnectionState.CONNECTING:
      case ConnectionState.RECONNECTING:
        return 'bg-warning-500 animate-pulse';
      case ConnectionState.FAILED:
        return 'bg-danger-500';
      default:
        return 'bg-gray-400';
    }
  };

  const getStatusText = () => {
    switch (state) {
      case ConnectionState.AUTHENTICATED:
        return 'Connected';
      case ConnectionState.CONNECTED:
        return 'Connected (authenticating...)';
      case ConnectionState.CONNECTING:
        return 'Connecting...';
      case ConnectionState.RECONNECTING:
        return 'Reconnecting...';
      case ConnectionState.FAILED:
        return 'Connection failed';
      default:
        return 'Disconnected';
    }
  };

  return (
    <div
      className={cn('relative', className)}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span
        className={cn(
          'block h-2.5 w-2.5 rounded-full transition-all duration-300',
          getDotColor()
        )}
      />

      {showTooltip && (
        <div className="absolute bottom-full right-0 mb-2 whitespace-nowrap rounded-md bg-dark-800 px-3 py-2 text-xs text-white shadow-lg z-50">
          <div className="flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', getDotColor())} />
            <span>{getStatusText()}</span>
          </div>
          {latency && isOnline && (
            <div className="mt-1 text-gray-400">
              Latency: {latency}ms
            </div>
          )}
          <div className="absolute right-2 top-full border-4 border-transparent border-t-dark-800" />
        </div>
      )}
    </div>
  );
};

/**
 * Connection status banner for displaying reconnection warnings
 */
export const ConnectionStatusBanner: React.FC = () => {
  const { state, reconnectAttempts, isOnline } = useConnectionStatus();
  const [dismissed, setDismissed] = useState(false);

  // Reset dismissed state when connection is restored
  useEffect(() => {
    if (isOnline) {
      setDismissed(false);
    }
  }, [isOnline]);

  // Only show for reconnecting or failed states
  if (isOnline || dismissed || (state !== ConnectionState.RECONNECTING && state !== ConnectionState.FAILED)) {
    return null;
  }

  const isFailed = state === ConnectionState.FAILED;

  return (
    <div
      className={cn(
        'fixed bottom-4 right-4 z-50 flex items-center gap-3 rounded-lg px-4 py-3 shadow-lg transition-all duration-300',
        isFailed
          ? 'bg-danger-600 text-white'
          : 'bg-warning-600 text-white'
      )}
    >
      {isFailed ? (
        <FiAlertCircle className="h-5 w-5" />
      ) : (
        <FiRefreshCw className="h-5 w-5 animate-spin" />
      )}

      <div>
        <p className="font-medium">
          {isFailed ? 'Connection Failed' : 'Reconnecting...'}
        </p>
        <p className="text-sm opacity-90">
          {isFailed
            ? 'Unable to establish connection. Please check your network.'
            : `Attempting to reconnect (${reconnectAttempts}/10)`}
        </p>
      </div>

      <button
        onClick={() => setDismissed(true)}
        className="ml-2 rounded p-1 hover:bg-white/20"
        aria-label="Dismiss"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
};

export default ConnectionStatusIndicator;
