/**
 * Apollo Platform - WebSocket Context Provider
 * Provides WebSocket connection management across the React application
 */

import React, { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { wsClient, ApolloWebSocketClient } from '@services/websocket/client';
import {
  WebSocketEventType,
  WebSocketChannel,
  ConnectionState,
  ConnectionInfo,
  AlertPayload,
  SurveillanceMatchPayload,
  BlockchainTransactionPayload,
} from '@services/websocket/types';
import { RootState } from '@store/index';
import { addAlert, updateAlert } from '@store/slices/alertsSlice';

interface WebSocketContextValue {
  // Connection state
  client: ApolloWebSocketClient;
  state: ConnectionState;
  isConnected: boolean;
  isAuthenticated: boolean;
  connectionInfo: ConnectionInfo;
  latency: number | undefined;

  // Connection management
  connect: (token?: string) => void;
  disconnect: () => void;
  reconnect: () => void;

  // Subscription management
  subscribeToAlerts: () => void;
  subscribeToSurveillance: () => void;
  subscribeToBlockchain: () => void;
  subscribeToInvestigation: (investigationId: string) => void;
  subscribeToOperation: (operationId: string) => void;
  unsubscribeFromInvestigation: (investigationId: string) => void;
  unsubscribeFromOperation: (operationId: string) => void;

  // Real-time data
  realtimeAlerts: AlertPayload[];
  surveillanceMatches: SurveillanceMatchPayload[];
  blockchainTransactions: BlockchainTransactionPayload[];

  // Utility
  clearRealtimeData: () => void;
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

interface WebSocketProviderProps {
  children: ReactNode;
  autoConnect?: boolean;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({
  children,
  autoConnect = true,
}) => {
  const dispatch = useDispatch();
  const { token } = useSelector((state: RootState) => state.auth);

  const [state, setState] = useState<ConnectionState>(wsClient.state);
  const [connectionInfo, setConnectionInfo] = useState<ConnectionInfo>(wsClient.getConnectionInfo());
  const [realtimeAlerts, setRealtimeAlerts] = useState<AlertPayload[]>([]);
  const [surveillanceMatches, setSurveillanceMatches] = useState<SurveillanceMatchPayload[]>([]);
  const [blockchainTransactions, setBlockchainTransactions] = useState<BlockchainTransactionPayload[]>([]);

  // Setup event listeners
  useEffect(() => {
    // Connection state changes
    const unsubStateChange = wsClient.on('connection:stateChange', ({ currentState }) => {
      setState(currentState);
      setConnectionInfo(wsClient.getConnectionInfo());
    });

    // Alert events
    const unsubAlertNew = wsClient.on<AlertPayload>(WebSocketEventType.ALERT_NEW, (alert) => {
      setRealtimeAlerts((prev) => [alert, ...prev.slice(0, 99)]);
      dispatch(addAlert(alert as any));
    });

    const unsubAlertUpdate = wsClient.on<AlertPayload>(WebSocketEventType.ALERT_UPDATE, (alert) => {
      setRealtimeAlerts((prev) =>
        prev.map((a) => (a.id === alert.id ? alert : a))
      );
      dispatch(updateAlert(alert as any));
    });

    // Surveillance events
    const unsubSurveillance = wsClient.on<SurveillanceMatchPayload>(
      WebSocketEventType.TARGET_SIGHTED,
      (match) => {
        setSurveillanceMatches((prev) => [match, ...prev.slice(0, 49)]);
      }
    );

    const unsubFacialMatch = wsClient.on<SurveillanceMatchPayload>(
      WebSocketEventType.FACIAL_MATCH,
      (match) => {
        setSurveillanceMatches((prev) => [match, ...prev.slice(0, 49)]);
      }
    );

    // Blockchain events
    const unsubTransaction = wsClient.on<BlockchainTransactionPayload>(
      WebSocketEventType.TRANSACTION_DETECTED,
      (tx) => {
        setBlockchainTransactions((prev) => [tx, ...prev.slice(0, 99)]);
      }
    );

    // Cleanup
    return () => {
      unsubStateChange();
      unsubAlertNew();
      unsubAlertUpdate();
      unsubSurveillance();
      unsubFacialMatch();
      unsubTransaction();
    };
  }, [dispatch]);

  // Auto-connect when authenticated
  useEffect(() => {
    if (autoConnect && token && !wsClient.isConnected) {
      wsClient.connect(token);
    }
  }, [autoConnect, token]);

  // Connection management
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

  // Subscription management
  const subscribeToAlerts = useCallback(() => {
    wsClient.subscribeToAlerts();
  }, []);

  const subscribeToSurveillance = useCallback(() => {
    wsClient.subscribeToSurveillance();
  }, []);

  const subscribeToBlockchain = useCallback(() => {
    wsClient.subscribeToBlockchain();
  }, []);

  const subscribeToInvestigation = useCallback((investigationId: string) => {
    wsClient.subscribeToInvestigation(investigationId);
  }, []);

  const subscribeToOperation = useCallback((operationId: string) => {
    wsClient.subscribeToOperation(operationId);
  }, []);

  const unsubscribeFromInvestigation = useCallback((investigationId: string) => {
    wsClient.unsubscribeFromInvestigation(investigationId);
  }, []);

  const unsubscribeFromOperation = useCallback((operationId: string) => {
    wsClient.unsubscribeFromOperation(operationId);
  }, []);

  // Utility
  const clearRealtimeData = useCallback(() => {
    setRealtimeAlerts([]);
    setSurveillanceMatches([]);
    setBlockchainTransactions([]);
  }, []);

  const value: WebSocketContextValue = {
    client: wsClient,
    state,
    isConnected: wsClient.isConnected,
    isAuthenticated: wsClient.isAuthenticated,
    connectionInfo,
    latency: wsClient.latency,
    connect,
    disconnect,
    reconnect,
    subscribeToAlerts,
    subscribeToSurveillance,
    subscribeToBlockchain,
    subscribeToInvestigation,
    subscribeToOperation,
    unsubscribeFromInvestigation,
    unsubscribeFromOperation,
    realtimeAlerts,
    surveillanceMatches,
    blockchainTransactions,
    clearRealtimeData,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

/**
 * Hook to access WebSocket context
 */
export const useWebSocketContext = (): WebSocketContextValue => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocketContext must be used within a WebSocketProvider');
  }
  return context;
};

/**
 * Hook to subscribe to specific channel on mount
 */
export const useChannelSubscription = (
  channel: WebSocketChannel,
  entityId?: string
) => {
  const { client, isAuthenticated } = useWebSocketContext();

  useEffect(() => {
    if (isAuthenticated) {
      client.subscribe(channel, entityId);

      return () => {
        client.unsubscribe(channel, entityId);
      };
    }
  }, [client, channel, entityId, isAuthenticated]);
};

export default WebSocketProvider;
