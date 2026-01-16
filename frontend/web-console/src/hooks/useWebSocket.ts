/**
 * Apollo Platform - WebSocket Hooks
 * React hooks for real-time WebSocket communication
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { wsClient, ApolloWebSocketClient } from '@services/websocket/client';
import {
  WebSocketEventType,
  WebSocketChannel,
  ConnectionState,
  ConnectionInfo,
  AlertPayload,
  SurveillanceMatchPayload,
  BlockchainTransactionPayload,
  InvestigationUpdatePayload,
  OperationStatusPayload,
  NotificationPayload,
  EventHandler,
  WebSocketMessage,
} from '@services/websocket/types';
import { RootState } from '@store/index';
import { addAlert, updateAlert } from '@store/slices/alertsSlice';

/**
 * Base WebSocket hook for event handling
 */
export const useWebSocket = <T = any>(
  event: string,
  handler: EventHandler<T>,
  deps: any[] = []
): ApolloWebSocketClient => {
  const memoizedHandler = useCallback(handler, [handler, ...deps]);

  useEffect(() => {
    const unsubscribe = wsClient.on(event, memoizedHandler);
    return unsubscribe;
  }, [event, memoizedHandler]);

  return wsClient;
};

/**
 * Hook for WebSocket connection management
 */
export const useWebSocketConnection = () => {
  const [connectionState, setConnectionState] = useState<ConnectionState>(wsClient.state);
  const [connectionInfo, setConnectionInfo] = useState<ConnectionInfo>(wsClient.getConnectionInfo());
  const { token } = useSelector((state: RootState) => state.auth);

  useEffect(() => {
    // Handle connection state changes
    const unsubscribe = wsClient.on('connection:stateChange', ({ currentState }) => {
      setConnectionState(currentState);
      setConnectionInfo(wsClient.getConnectionInfo());
    });

    return unsubscribe;
  }, []);

  // Auto-connect when authenticated
  useEffect(() => {
    if (token && !wsClient.isConnected) {
      wsClient.connect(token);
    }
  }, [token]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      // Don't disconnect on unmount - let the app manage the connection
    };
  }, []);

  const connect = useCallback((authToken?: string) => {
    wsClient.connect(authToken || token || undefined);
  }, [token]);

  const disconnect = useCallback(() => {
    wsClient.disconnect();
  }, []);

  const reconnect = useCallback(() => {
    wsClient.disconnect();
    setTimeout(() => {
      wsClient.connect(token || undefined);
    }, 100);
  }, [token]);

  return {
    state: connectionState,
    info: connectionInfo,
    isConnected: wsClient.isConnected,
    isAuthenticated: wsClient.isAuthenticated,
    latency: wsClient.latency,
    connect,
    disconnect,
    reconnect,
    client: wsClient,
  };
};

/**
 * Hook for real-time alerts
 */
export const useAlerts = () => {
  const dispatch = useDispatch();
  const [realtimeAlerts, setRealtimeAlerts] = useState<AlertPayload[]>([]);
  const alertsRef = useRef<AlertPayload[]>([]);

  useEffect(() => {
    // Subscribe to alerts channel
    if (wsClient.isAuthenticated) {
      wsClient.subscribeToAlerts();
    }

    // Handle new alerts
    const unsubNewAlert = wsClient.on<AlertPayload>(WebSocketEventType.ALERT_NEW, (alert) => {
      alertsRef.current = [alert, ...alertsRef.current.slice(0, 99)]; // Keep last 100
      setRealtimeAlerts([...alertsRef.current]);
      dispatch(addAlert(alert as any));
    });

    // Handle alert updates
    const unsubUpdateAlert = wsClient.on<AlertPayload>(WebSocketEventType.ALERT_UPDATE, (alert) => {
      alertsRef.current = alertsRef.current.map(a =>
        a.id === alert.id ? alert : a
      );
      setRealtimeAlerts([...alertsRef.current]);
      dispatch(updateAlert(alert as any));
    });

    // Handle acknowledgments
    const unsubAckAlert = wsClient.on(WebSocketEventType.ALERT_ACKNOWLEDGE, ({ alertId, acknowledgedBy }) => {
      alertsRef.current = alertsRef.current.map(a =>
        a.id === alertId ? { ...a, status: 'acknowledged' as const } : a
      );
      setRealtimeAlerts([...alertsRef.current]);
    });

    return () => {
      unsubNewAlert();
      unsubUpdateAlert();
      unsubAckAlert();
    };
  }, [dispatch]);

  const acknowledgeAlert = useCallback((alertId: string) => {
    wsClient.sendMessage({
      type: 'alert:acknowledge',
      channel: WebSocketChannel.ALERTS,
      payload: { alertId },
      timestamp: new Date().toISOString(),
      messageId: `${Date.now()}`,
    });
  }, []);

  const clearAlerts = useCallback(() => {
    alertsRef.current = [];
    setRealtimeAlerts([]);
  }, []);

  return {
    alerts: realtimeAlerts,
    acknowledgeAlert,
    clearAlerts,
    unreadCount: realtimeAlerts.filter(a => a.status === 'new').length,
    criticalCount: realtimeAlerts.filter(a => a.severity === 'critical' && a.status === 'new').length,
  };
};

/**
 * Hook for real-time surveillance feed
 */
export const useSurveillance = () => {
  const [matches, setMatches] = useState<SurveillanceMatchPayload[]>([]);
  const [isLive, setIsLive] = useState(false);
  const matchesRef = useRef<SurveillanceMatchPayload[]>([]);

  useEffect(() => {
    // Subscribe to surveillance channel
    if (wsClient.isAuthenticated) {
      wsClient.subscribeToSurveillance();
      setIsLive(true);
    }

    // Handle target sightings
    const unsubSighting = wsClient.on<SurveillanceMatchPayload>(
      WebSocketEventType.TARGET_SIGHTED,
      (match) => {
        matchesRef.current = [match, ...matchesRef.current.slice(0, 49)]; // Keep last 50
        setMatches([...matchesRef.current]);
      }
    );

    // Handle facial matches
    const unsubFacial = wsClient.on<SurveillanceMatchPayload>(
      WebSocketEventType.FACIAL_MATCH,
      (match) => {
        matchesRef.current = [match, ...matchesRef.current.slice(0, 49)];
        setMatches([...matchesRef.current]);
      }
    );

    return () => {
      unsubSighting();
      unsubFacial();
      setIsLive(false);
    };
  }, []);

  const clearMatches = useCallback(() => {
    matchesRef.current = [];
    setMatches([]);
  }, []);

  const highConfidenceMatches = matches.filter(m => m.confidence >= 0.85);
  const recentMatches = matches.filter(m => {
    const matchTime = new Date(m.timestamp).getTime();
    return Date.now() - matchTime < 3600000; // Last hour
  });

  return {
    matches,
    highConfidenceMatches,
    recentMatches,
    isLive,
    clearMatches,
    matchCount: matches.length,
  };
};

/**
 * Hook for real-time blockchain monitoring
 */
export const useBlockchain = () => {
  const [transactions, setTransactions] = useState<BlockchainTransactionPayload[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const transactionsRef = useRef<BlockchainTransactionPayload[]>([]);

  useEffect(() => {
    // Subscribe to blockchain channel
    if (wsClient.isAuthenticated) {
      wsClient.subscribeToBlockchain();
      setIsMonitoring(true);
    }

    // Handle new transactions
    const unsubTransaction = wsClient.on<BlockchainTransactionPayload>(
      WebSocketEventType.TRANSACTION_DETECTED,
      (tx) => {
        transactionsRef.current = [tx, ...transactionsRef.current.slice(0, 99)];
        setTransactions([...transactionsRef.current]);
      }
    );

    // Handle wallet activity
    const unsubWallet = wsClient.on(WebSocketEventType.WALLET_ACTIVITY, (activity) => {
      // Handle wallet activity updates
    });

    // Handle mixer detection
    const unsubMixer = wsClient.on(WebSocketEventType.MIXER_DETECTED, (detection) => {
      // Handle mixer detection
    });

    return () => {
      unsubTransaction();
      unsubWallet();
      unsubMixer();
      setIsMonitoring(false);
    };
  }, []);

  const clearTransactions = useCallback(() => {
    transactionsRef.current = [];
    setTransactions([]);
  }, []);

  const flaggedTransactions = transactions.filter(tx => tx.flags.length > 0 || tx.riskScore >= 70);
  const totalVolume = transactions.reduce((sum, tx) => sum + (tx.usdValue || 0), 0);

  return {
    transactions,
    flaggedTransactions,
    isMonitoring,
    clearTransactions,
    totalVolume,
    transactionCount: transactions.length,
  };
};

/**
 * Hook for real-time investigation updates
 */
export const useInvestigation = (investigationId: string) => {
  const [updates, setUpdates] = useState<InvestigationUpdatePayload[]>([]);
  const [isSubscribed, setIsSubscribed] = useState(false);

  useEffect(() => {
    if (!investigationId) return;

    // Subscribe to specific investigation
    if (wsClient.isAuthenticated) {
      wsClient.subscribeToInvestigation(investigationId);
      setIsSubscribed(true);
    }

    // Handle investigation updates
    const unsubUpdate = wsClient.on<InvestigationUpdatePayload>(
      WebSocketEventType.INVESTIGATION_UPDATE,
      (update) => {
        if (update.investigationId === investigationId) {
          setUpdates(prev => [update, ...prev.slice(0, 49)]);
        }
      }
    );

    // Handle evidence added
    const unsubEvidence = wsClient.on(WebSocketEventType.EVIDENCE_ADDED, (payload) => {
      if (payload.investigationId === investigationId) {
        setUpdates(prev => [{
          investigationId,
          caseNumber: payload.caseNumber,
          title: 'Evidence Added',
          updateType: 'evidence',
          newValue: payload.evidence,
          updatedBy: payload.addedBy,
          timestamp: new Date().toISOString(),
          summary: `New evidence added: ${payload.evidence.title}`,
        }, ...prev.slice(0, 49)]);
      }
    });

    return () => {
      wsClient.unsubscribeFromInvestigation(investigationId);
      unsubUpdate();
      unsubEvidence();
      setIsSubscribed(false);
    };
  }, [investigationId]);

  const clearUpdates = useCallback(() => {
    setUpdates([]);
  }, []);

  return {
    updates,
    isSubscribed,
    clearUpdates,
    latestUpdate: updates[0],
  };
};

/**
 * Hook for real-time operation status
 */
export const useOperation = (operationId: string) => {
  const [status, setStatus] = useState<OperationStatusPayload | null>(null);
  const [statusHistory, setStatusHistory] = useState<OperationStatusPayload[]>([]);
  const [isSubscribed, setIsSubscribed] = useState(false);

  useEffect(() => {
    if (!operationId) return;

    // Subscribe to specific operation
    if (wsClient.isAuthenticated) {
      wsClient.subscribeToOperation(operationId);
      setIsSubscribed(true);
    }

    // Handle operation status updates
    const unsubStatus = wsClient.on<OperationStatusPayload>(
      WebSocketEventType.OPERATION_STATUS,
      (update) => {
        if (update.operationId === operationId) {
          setStatus(update);
          setStatusHistory(prev => [update, ...prev.slice(0, 19)]);
        }
      }
    );

    // Handle field reports
    const unsubReport = wsClient.on(WebSocketEventType.FIELD_REPORT, (report) => {
      if (report.operationId === operationId) {
        // Handle field report
      }
    });

    return () => {
      wsClient.unsubscribeFromOperation(operationId);
      unsubStatus();
      unsubReport();
      setIsSubscribed(false);
    };
  }, [operationId]);

  return {
    status,
    statusHistory,
    isSubscribed,
    isActive: status?.status === 'in_progress',
  };
};

/**
 * Hook for real-time notifications
 */
export const useNotifications = () => {
  const [notifications, setNotifications] = useState<NotificationPayload[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const notificationsRef = useRef<NotificationPayload[]>([]);

  useEffect(() => {
    // Handle new notifications
    const unsubNotification = wsClient.on<NotificationPayload>(
      WebSocketEventType.NOTIFICATION,
      (notification) => {
        notificationsRef.current = [notification, ...notificationsRef.current.slice(0, 49)];
        setNotifications([...notificationsRef.current]);
        setUnreadCount(prev => prev + 1);
      }
    );

    return () => {
      unsubNotification();
    };
  }, []);

  const markAsRead = useCallback((notificationId: string) => {
    notificationsRef.current = notificationsRef.current.map(n =>
      n.id === notificationId ? { ...n, read: true } : n
    );
    setNotifications([...notificationsRef.current]);
    setUnreadCount(prev => Math.max(0, prev - 1));
  }, []);

  const markAllAsRead = useCallback(() => {
    notificationsRef.current = notificationsRef.current.map(n => ({ ...n, read: true }));
    setNotifications([...notificationsRef.current]);
    setUnreadCount(0);
  }, []);

  const clearNotifications = useCallback(() => {
    notificationsRef.current = [];
    setNotifications([]);
    setUnreadCount(0);
  }, []);

  return {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    clearNotifications,
  };
};

/**
 * Hook for subscribing to multiple events
 */
export const useMultipleEvents = (
  events: Array<{ event: string; handler: EventHandler }>
) => {
  useEffect(() => {
    const unsubscribers = events.map(({ event, handler }) =>
      wsClient.on(event, handler)
    );

    return () => {
      unsubscribers.forEach(unsub => unsub());
    };
  }, [events]);
};

/**
 * Hook for connection status indicator
 */
export const useConnectionStatus = () => {
  const [state, setState] = useState<ConnectionState>(wsClient.state);
  const [latency, setLatency] = useState<number | undefined>(wsClient.latency);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);

  useEffect(() => {
    const unsubState = wsClient.on('connection:stateChange', ({ currentState }) => {
      setState(currentState);
    });

    const unsubReconnect = wsClient.on('connection:reconnecting', ({ attempt }) => {
      setReconnectAttempts(attempt);
    });

    // Update latency periodically
    const latencyInterval = setInterval(() => {
      setLatency(wsClient.latency);
    }, 5000);

    return () => {
      unsubState();
      unsubReconnect();
      clearInterval(latencyInterval);
    };
  }, []);

  const statusText = {
    [ConnectionState.CONNECTING]: 'Connecting...',
    [ConnectionState.CONNECTED]: 'Connected',
    [ConnectionState.AUTHENTICATED]: 'Online',
    [ConnectionState.DISCONNECTED]: 'Offline',
    [ConnectionState.RECONNECTING]: `Reconnecting (${reconnectAttempts})...`,
    [ConnectionState.FAILED]: 'Connection Failed',
  };

  const statusColor = {
    [ConnectionState.CONNECTING]: 'yellow',
    [ConnectionState.CONNECTED]: 'blue',
    [ConnectionState.AUTHENTICATED]: 'green',
    [ConnectionState.DISCONNECTED]: 'gray',
    [ConnectionState.RECONNECTING]: 'orange',
    [ConnectionState.FAILED]: 'red',
  };

  return {
    state,
    latency,
    reconnectAttempts,
    statusText: statusText[state] || 'Unknown',
    statusColor: statusColor[state] || 'gray',
    isOnline: state === ConnectionState.AUTHENTICATED,
  };
};

export default useWebSocket;
