import { useContext } from 'react';
import { NotificationContext } from './notificationContextBase';
import type { NotificationContextType } from './notificationContextBase';

export const useNotification = (): NotificationContextType => {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};
