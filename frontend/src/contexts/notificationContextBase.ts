import { createContext } from 'react';

export type NotificationType = 'success' | 'error' | 'info' | 'warning';

export interface NotificationState {
  id: string;
  message: string;
  type: NotificationType;
  isVisible: boolean;
  duration?: number;
}

export interface NotificationContextType {
  notification: NotificationState | null;
  showNotification: (message: string, type: NotificationType, duration?: number) => void;
  hideNotification: (id?: string) => void;
}

export const NotificationContext = createContext<NotificationContextType | undefined>(undefined);
