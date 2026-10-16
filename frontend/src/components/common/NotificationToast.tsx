import React, { useEffect, useState } from 'react';
import { CircleAlert, CircleCheck, CircleX, Info, X } from 'lucide-react';
import { useNotification } from '../../contexts/useNotification';
import type { NotificationType } from '../../contexts/notificationContextBase';

const TITLE_BY_TYPE: Record<NotificationType, string> = {
  success: 'Success',
  warning: 'Attention',
  error: 'Action failed',
  info: 'Information',
};

const toneClass = (type: NotificationType) => {
  if (type === 'success') return 'border-emerald-500/40 bg-emerald-500/12 text-emerald-100';
  if (type === 'warning') return 'border-amber-500/40 bg-amber-500/12 text-amber-100';
  if (type === 'error') return 'border-red-500/40 bg-red-500/12 text-red-100';
  return 'border-cyan-500/40 bg-cyan-500/12 text-cyan-100';
};

const iconForType = (type: NotificationType) => {
  if (type === 'success') return <CircleCheck className="h-5 w-5" aria-hidden="true" />;
  if (type === 'warning') return <CircleAlert className="h-5 w-5" aria-hidden="true" />;
  if (type === 'error') return <CircleX className="h-5 w-5" aria-hidden="true" />;
  return <Info className="h-5 w-5" aria-hidden="true" />;
};

const NotificationToast: React.FC = () => {
  const { notification, hideNotification } = useNotification();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!notification) {
      setVisible(false);
      return;
    }
    setVisible(Boolean(notification.isVisible));
  }, [notification]);

  if (!notification) return null;

  return (
    <div
      className={`fixed right-4 top-4 z-[100] transition-all duration-200 ease-out sm:right-6 sm:top-6 ${
        visible ? 'translate-y-0 opacity-100' : '-translate-y-2 opacity-0'
      }`}
      role="status"
      aria-live={notification.type === 'error' ? 'assertive' : 'polite'}
      aria-atomic="true"
    >
      <div
        className={`w-[calc(100vw-2rem)] max-w-md rounded-xl border shadow-2xl backdrop-blur ${toneClass(
          notification.type
        )}`}
      >
        <div className="flex items-start gap-3 p-4">
          <div className="mt-0.5">{iconForType(notification.type)}</div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold">{TITLE_BY_TYPE[notification.type]}</p>
            <p className="mt-1 text-sm leading-relaxed break-words">{notification.message}</p>
          </div>
          <button
            type="button"
            onClick={() => hideNotification(notification.id)}
            className="rounded-md p-1 text-current/80 transition hover:bg-black/20 hover:text-current"
            aria-label="Dismiss notification"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default NotificationToast;
