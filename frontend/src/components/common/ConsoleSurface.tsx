import type { ReactNode } from 'react';

export const Surface = ({
  title,
  description,
  actions,
  children,
  className = '',
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) => {
  return (
    <section className={`rounded-2xl border border-border-dark/70 bg-dark-secondary/80 shadow-[0_18px_50px_rgba(0,0,0,0.22)] backdrop-blur ${className}`}>
      {(title || description || actions) ? (
        <div className="flex flex-col gap-3 border-b border-border-dark/70 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            {title ? <h2 className="text-base font-semibold text-white">{title}</h2> : null}
            {description ? <p className="mt-1 text-sm text-text-secondary">{description}</p> : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <div className="p-5">{children}</div>
    </section>
  );
};

export const ActionButton = ({
  children,
  onClick,
  disabled,
  variant = 'secondary',
  type = 'button',
  className = '',
  ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void | Promise<void>;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  type?: 'button' | 'submit' | 'reset';
  className?: string;
  ariaLabel?: string;
}) => {
  const variantClass =
    variant === 'primary'
      ? 'border-cyan-400/30 bg-cyan-500/10 text-cyan-200 hover:border-cyan-300/50 hover:bg-cyan-500/20'
      : variant === 'danger'
        ? 'border-red-500/30 bg-red-500/10 text-red-200 hover:border-red-400/60 hover:bg-red-500/20'
        : variant === 'ghost'
          ? 'border-border-dark/40 bg-transparent text-text-secondary hover:border-border-dark/80 hover:bg-dark-tertiary/70 hover:text-white'
          : 'border-border-dark/70 bg-dark-tertiary text-white hover:border-cyan-400/40 hover:bg-dark-tertiary/90';

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className={`rounded-xl border px-3 py-2 text-sm transition disabled:cursor-not-allowed disabled:opacity-50 ${variantClass} ${className}`}
    >
      {children}
    </button>
  );
};

export const StatTile = ({
  label,
  value,
  tone = 'neutral',
  meta,
  onClick,
  selected = false,
  ariaLabel,
}: {
  label: string;
  value: string | number;
  tone?: 'neutral' | 'danger' | 'warning' | 'success' | 'info';
  meta?: string;
  onClick?: () => void;
  selected?: boolean;
  ariaLabel?: string;
}) => {
  const toneClass = {
    neutral: 'border-border-dark/70',
    danger: 'border-red-500/30 bg-red-500/5',
    warning: 'border-amber-500/30 bg-amber-500/5',
    success: 'border-emerald-500/30 bg-emerald-500/5',
    info: 'border-cyan-500/30 bg-cyan-500/5',
  }[tone];

  const className = `rounded-2xl border ${toneClass} bg-dark-tertiary/70 p-4 ${
    selected ? 'ring-2 ring-cyan-300/60 ring-offset-2 ring-offset-dark-primary' : ''
  } ${onClick ? 'cursor-pointer text-left transition hover:-translate-y-0.5 hover:border-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-300/70 focus:ring-offset-2 focus:ring-offset-dark-primary' : ''}`;
  const content = (
    <>
      <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">{label}</p>
      <p className="mt-3 text-2xl font-semibold text-white">{value}</p>
      {meta ? <p className="mt-2 text-xs text-text-secondary">{meta}</p> : null}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        aria-label={ariaLabel || `Show details for ${label}`}
        aria-pressed={selected}
        className={className}
      >
        {content}
      </button>
    );
  }

  return (
    <div className={className}>{content}</div>
  );
};

export const StatusPill = ({ label, tone = 'neutral' }: { label: string; tone?: 'neutral' | 'danger' | 'warning' | 'success' | 'info' }) => {
  const cls = {
    neutral: 'border-gray-600/60 bg-dark-tertiary/80 text-gray-200',
    danger: 'border-red-500/30 bg-red-500/10 text-red-200',
    warning: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
    success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    info: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
  }[tone];
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${cls}`}>{label}</span>;
};

export const EmptyState = ({ title, description }: { title: string; description: string }) => (
  <StateCard title={title} description={description} tone="neutral" />
);

export const StateCard = ({
  title,
  description,
  tone = 'info',
  actionLabel,
  onAction,
}: {
  title: string;
  description?: string;
  tone?: 'info' | 'warning' | 'danger' | 'neutral';
  actionLabel?: string;
  onAction?: () => void;
}) => {
  const toneClass = {
    info: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-100',
    warning: 'border-amber-500/30 bg-amber-500/10 text-amber-100',
    danger: 'border-red-500/30 bg-red-500/10 text-red-100',
    neutral: 'border-border-dark/70 bg-dark-tertiary/40 text-text-secondary',
  }[tone];

  return (
    <div className={`rounded-2xl border p-4 text-sm ${toneClass}`} role="status" aria-live="polite">
      <p className="font-medium">{title}</p>
      {description ? <p className="mt-1 text-sm opacity-90">{description}</p> : null}
      {actionLabel && onAction ? (
        <div className="mt-3">
          <ActionButton onClick={onAction} variant="ghost" className="border-current/30 text-current hover:bg-black/10">
            {actionLabel}
          </ActionButton>
        </div>
      ) : null}
    </div>
  );
};

export const StateNotice = StateCard;

export const LoadingState = ({
  label = 'Loading data from backend...',
}: {
  label?: string;
}) => (
  <StateCard tone="info" title="Loading" description={label} />
);

export const ErrorState = ({
  message,
  onRetry,
  retryLabel = 'Retry',
}: {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
}) => (
  <StateCard tone="danger" title="Something went wrong" description={message} actionLabel={onRetry ? retryLabel : undefined} onAction={onRetry} />
);
