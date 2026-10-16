import { useContext } from 'react';
import { WebSocketContext } from './webSocketContextBase';
import type { WebSocketContextValue } from './webSocketContextBase';

export const useWebSocket = (): WebSocketContextValue | null => {
  return useContext(WebSocketContext);
};
