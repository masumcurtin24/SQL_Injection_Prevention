import * as React from 'react';
import { getAuditEvents } from '../../lib/apiClient';
import { Surface, StatusPill, EmptyState, ErrorState } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import { userDisplayMeta, userDisplayName } from '../../lib/userDisplay';
import type { AuditLogItem } from '../../types/api';
import { useAppStore } from '../../store/appStore';

const PAGE_SIZE = 25;

const isoInputFromDate = (date: Date): string => {
  const d = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
};

const defaultStartForRange = (range: '24h' | '7d' | '30d' | 'total'): string => {
  if (range === 'total') return '';
  const now = new Date();
  const days = range === '24h' ? 1 : range === '7d' ? 7 : 30;
  now.setDate(now.getDate() - days);
  return isoInputFromDate(now);
};

const AuditLogPage = ({ role }: { role: string }) => {
  const isAdmin = role === 'admin';
  const globalTimeRange = useAppStore((state) => state.globalTimeRange);

  const [items, setItems] = React.useState<AuditLogItem[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [errorText, setErrorText] = React.useState('');
  const [action, setAction] = React.useState('');
  const [actorUserId, setActorUserId] = React.useState('');
  const [startDate, setStartDate] = React.useState<string>(() => defaultStartForRange(globalTimeRange));
  const [endDate, setEndDate] = React.useState<string>(() => isoInputFromDate(new Date()));
  const [page, setPage] = React.useState(1);
  const [total, setTotal] = React.useState(0);

  const loadAudit = React.useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setErrorText('');
    try {
      const offset = (page - 1) * PAGE_SIZE;
      const payload = await getAuditEvents({
        limit: PAGE_SIZE,
        offset,
        action: action.trim() || undefined,
        actor_user_id: actorUserId.trim() || undefined,
        start_date: startDate ? new Date(startDate).toISOString() : undefined,
        end_date: endDate ? new Date(endDate).toISOString() : undefined,
      });
      setItems(payload.data.items || []);
      setTotal(Number(payload.data.total || 0));
    } catch (error: any) {
      setItems([]);
      setTotal(0);
      setErrorText(String(error?.response?.data?.detail || 'Failed to load audit events.'));
    } finally {
      setLoading(false);
    }
  }, [action, actorUserId, endDate, isAdmin, page, startDate]);

  React.useEffect(() => {
    if (!isAdmin) return;
    setPage(1);
    setStartDate(defaultStartForRange(globalTimeRange));
    setEndDate(isoInputFromDate(new Date()));
  }, [globalTimeRange, isAdmin]);

  React.useEffect(() => {
    void loadAudit();
  }, [loadAudit]);

  if (!isAdmin) {
    return <EmptyState title="Audit log restricted" description="Only admin users can review platform audit events." />;
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Surface
      title="Audit log"
      description="Immutable record of privileged actions across alerts, defender operations, and configuration changes."
      actions={
        <>
          <input
            value={action}
            onChange={(e) => {
              setAction(e.target.value);
              setPage(1);
            }}
            placeholder="Action"
            className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
          />
          <input
            value={actorUserId}
            onChange={(e) => {
              setActorUserId(e.target.value);
              setPage(1);
            }}
            placeholder="Actor user id (optional)"
            className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
          />
          <input
            type="datetime-local"
            value={startDate}
            onChange={(e) => {
              setStartDate(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none"
          />
          <input
            type="datetime-local"
            value={endDate}
            onChange={(e) => {
              setEndDate(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none"
          />
          <button
            type="button"
            onClick={() => void loadAudit()}
            className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-200"
          >
            Refresh
          </button>
        </>
      }
    >
      {errorText ? (
        <div className="mb-4">
          <ErrorState message={errorText} />
        </div>
      ) : null}
      <div className="overflow-hidden rounded-2xl border border-border-dark/70">
        <table className="min-w-full divide-y divide-border-dark/70 text-sm">
          <thead className="bg-dark-tertiary/90 text-text-secondary">
            <tr>
              <th className="px-4 py-3 text-left font-medium">Timestamp</th>
              <th className="px-4 py-3 text-left font-medium">Action</th>
              <th className="px-4 py-3 text-left font-medium">Actor</th>
              <th className="px-4 py-3 text-left font-medium">Resource</th>
              <th className="px-4 py-3 text-left font-medium">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-dark/60 bg-[#0d1729]/60">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-text-secondary">
                  Loading audit events...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-text-secondary">
                  No audit events matched your filters.
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <tr key={item.id}>
                  <td className="px-4 py-3 text-text-secondary">{formatTimestamp(item.timestamp)}</td>
                  <td className="px-4 py-3 text-white">{item.action}</td>
                  <td className="px-4 py-3 text-text-secondary">
                    <div className="text-white">{userDisplayName(item.actor, item.actor_user_id, 'system')}</div>
                    {item.actor_user_id || item.actor?.role ? (
                      <div className="text-xs text-text-secondary">{userDisplayMeta(item.actor, item.actor_user_id)}</div>
                    ) : null}
                  </td>
                  <td className="px-4 py-3 text-text-secondary">{item.resource_type || 'resource'} / {item.resource_id || '-'}</td>
                  <td className="px-4 py-3"><StatusPill label={item.success ? 'Success' : 'Failed'} tone={item.success ? 'success' : 'danger'} /></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center justify-between text-xs text-text-secondary">
        <span>
          Page {page} of {totalPages} ({total} records)
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={loading || page <= 1}
            onClick={() => setPage((prev) => Math.max(1, prev - 1))}
            className="rounded border border-border-dark/70 px-2 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={loading || page >= totalPages}
            onClick={() => setPage((prev) => prev + 1)}
            className="rounded border border-border-dark/70 px-2 py-1 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </Surface>
  );
};

export default AuditLogPage;
