import { createContext } from 'react';

export type WSStatus = 'connecting' | 'connected' | 'disconnected';

export interface WebSocketContextValue {
  status: WSStatus;
}

export const WebSocketContext = createContext<WebSocketContextValue | null>(null);
