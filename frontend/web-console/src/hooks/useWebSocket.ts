import { useEffect, useCallback } from 'react';
import { wsClient } from '@services/websocket/client';

type EventHandler = (data: any) => void;

export const useWebSocket = (event: string, handler: EventHandler) => {
  const memoizedHandler = useCallback(handler, [handler]);

  useEffect(() => {
    wsClient.on(event, memoizedHandler);
    return () => {
      wsClient.off(event, memoizedHandler);
    };
  }, [event, memoizedHandler]);

  return wsClient;
};

export default useWebSocket;
