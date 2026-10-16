// frontend/src/contexts/NotificationContext.tsx
import { useState, useCallback, useEffect } from 'react';
import type { ReactNode } from 'react';
import { NotificationContext } from './notificationContextBase';
import type { NotificationContextType, NotificationState, NotificationType } from './notificationContextBase';

interface NotificationProviderProps {
  children: ReactNode;
}

let notificationTimer: ReturnType<typeof setTimeout> | null = null;

export const NotificationProvider = ({ children }: NotificationProviderProps) => {
  const [notification, setNotification] = useState<NotificationState | null>(null);

  const hideNotification = useCallback((idToHide?: string) => {
    setNotification(prev => {
      // If an id is provided, only hide if it matches the current notification's id
      if (idToHide && prev && prev.id !== idToHide) {
        return prev; // Don't hide if IDs don't match
      }
      // If no id or id matches, proceed to hide
      if (prev) {
        return { ...prev, isVisible: false };
      }
      return null;
    });
  }, []);

  const showNotification = useCallback((
    message: string,
    type: NotificationType,
    duration: number = 5000 // Default duration 5 seconds
  ) => {
    // Clear any existing timer to prevent premature hiding of the new notification
    if (notificationTimer) {
      clearTimeout(notificationTimer);
    }

    const newNotificationId = `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    setNotification({ id: newNotificationId, message, type, isVisible: true, duration });

    // Set a timer to hide the notification automatically
    notificationTimer = setTimeout(() => {
      hideNotification(newNotificationId); // Pass ID to ensure we hide the correct one
    }, duration);
  }, [hideNotification]); // hideNotification is a dependency

  // Effect to clear the notification completely after it has faded out (optional)
  // This depends on your CSS transition duration for fading out.
  useEffect(() => {
    if (notification && !notification.isVisible) {
      const fadeOutTimer = setTimeout(() => {
        // Only clear if it's still the same notification that was made invisible
        setNotification(prev => (prev && prev.id === notification.id && !prev.isVisible ? null : prev));
      }, 500); // Matches typical fade-out duration (e.g., 0.5s)

      return () => clearTimeout(fadeOutTimer);
    }
  }, [notification]);


  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (notificationTimer) {
        clearTimeout(notificationTimer);
      }
    };
  }, []);

  const contextValue: NotificationContextType = {
    notification,
    showNotification,
    hideNotification,
  };

  return (
    <NotificationContext.Provider value={contextValue}>
      {children}
    </NotificationContext.Provider>
  );
};
