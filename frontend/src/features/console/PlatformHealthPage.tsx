import * as React from 'react';
import { ResponsiveContainer, LineChart, Line, CartesianGrid, Tooltip, XAxis, BarChart, Bar } from 'recharts';
import { getDashboardPlatformHealth, getMonitoringFalsePositiveTrends } from '../../lib/apiClient';
import { useAppStore } from '../../store/appStore';
import { ActionButton, Surface, StatTile, StatusPill, EmptyState, ErrorState, LoadingState } from '../../components/common/ConsoleSurface';
import type { DashboardPlatformHealthResponse, PlatformHealthEndpointMetric } from '../../types/api';

const fpDaysFromRange = (range: '24h' | '7d' | '30d' | 'total'): number => {
  if (range === '24h') return 14;
  if (range === '7d') return 14;
  if (range === '30d') return 30;
  return 60;
};

const toneForStatus = (status: string | undefined) => {
  const value = String(status || '').toLowerCase();
  if (value === 'critical') return 'danger' as const;
  if (value === 'degraded') return 'warning' as const;
  if (value === 'healthy') return 'success' as const;
  return 'neutral' as const;
};

const PlatformHealthPage = ({ role }: { role: string }) => {
  const privileged = role === 'reviewer' || role === 'analyst' || role === 'admin';
  const globalTimeRange = useAppStore((state) => state.globalTimeRange);
  const fpDays = fpDaysFromRange(globalTimeRange);

  const [health, setHealth] = React.useState<DashboardPlatformHealthResponse | null>(null);
  const [fpSeries, setFpSeries] = React.useState<any[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [errorText, setErrorText] = React.useState('');

  const loadData = React.useCallback(async () => {
    if (!privileged) return;
    setLoading(true);
    setErrorText('');
    try {
      const [healthRes, fpRes] = await Promise.all([
        getDashboardPlatformHealth(20, fpDays, true),
        getMonitoringFalsePositiveTrends(fpDays, true),
      ]);
      setHealth(healthRes.data || null);
      setFpSeries(fpRes.data?.series || []);
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to load platform health data.'));
    } finally {
      setLoading(false);
    }
  }, [fpDays, privileged]);

  React.useEffect(() => {
    void loadData();
    if (!privileged) return;
    const timerId = window.setInterval(() => {
      void loadData();
    }, 30000);
    return () => window.clearInterval(timerId);
  }, [loadData, privileged]);

  if (!privileged) {
    return <EmptyState title="Platform health is restricted" description="Viewer users do not have access to monitoring and operational telemetry." />;
  }

  const http = health?.components?.http;
  const websocket = health?.components?.websocket;
  const queue = health?.components?.queue;
  const models = health?.components?.models;
  const quality = health?.components?.quality;

  const endpointRows: PlatformHealthEndpointMetric[] = [
    ...(http?.top_slow_endpoints || []),
    ...(http?.top_error_endpoints || []),
  ].filter((row, index, arr) => {
    const key = `${row.method || ''}:${row.path || ''}`;
    return arr.findIndex((item) => `${item.method || ''}:${item.path || ''}` === key) === index;
  });

  return (
    <div className="space-y-6">
      {errorText ? (
        <ErrorState message={errorText} onRetry={() => void loadData()} />
      ) : null}

      {loading && !health ? (
        <LoadingState label="Loading platform telemetry and component health..." />
      ) : null}

      {!loading && !health ? (
        <EmptyState
          title="No platform health snapshot"
          description="Health telemetry is not available yet. Retry after traffic or worker activity is present."
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <StatTile label="Health score" value={health?.score ?? '-'} tone={(health?.score || 0) >= 80 ? 'success' : (health?.score || 0) >= 60 ? 'warning' : 'danger'} meta={String(health?.overall_status || 'unknown')} />
        <StatTile label="HTTP requests" value={http?.requests_total ?? '-'} tone="info" meta="Telemetry total" />
        <StatTile label="HTTP errors" value={http?.errors_total ?? '-'} tone={(http?.errors_total || 0) > 0 ? 'warning' : 'success'} meta={`Error rate ${Number(http?.error_rate || 0).toFixed(3)}`} />
        <StatTile label="WS active" value={websocket?.active_connections ?? '-'} tone="info" meta="Connected clients" />
        <StatTile label="Queue usage" value={queue?.utilization != null ? `${Math.round(Number(queue.utilization) * 100)}%` : '-'} tone={(queue?.utilization || 0) > 0.85 ? 'danger' : (queue?.utilization || 0) > 0.6 ? 'warning' : 'success'} meta={`Dead-letter ${queue?.dead_letter ?? 0}`} />
        <StatTile label="Pending feedback" value={models?.pending_feedback ?? '-'} tone={(models?.pending_feedback || 0) > 0 ? 'warning' : 'success'} meta={`FP rate ${(Number(quality?.global_false_positive_rate || 0) * 100).toFixed(1)}%`} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <Surface
          title="Component status"
          description="Backend-computed health status for HTTP, websocket, queue, model lifecycle, and quality."
          actions={
            <ActionButton
              onClick={() => void loadData()}
              disabled={loading}
              variant="primary"
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </ActionButton>
          }
        >
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">HTTP</p>
              <div className="mt-3">
                <StatusPill label={String(http?.status || 'unknown')} tone={toneForStatus(http?.status)} />
              </div>
              <p className="mt-2 text-xs text-text-secondary">Avg latency {Math.round(Number(http?.avg_latency_ms || 0))} ms</p>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Websocket</p>
              <div className="mt-3">
                <StatusPill label={String(websocket?.status || 'unknown')} tone={toneForStatus(websocket?.status)} />
              </div>
              <p className="mt-2 text-xs text-text-secondary">Failure rate {Number(websocket?.broadcast_failure_rate || 0).toFixed(3)}</p>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Queue</p>
              <div className="mt-3">
                <StatusPill label={String(queue?.status || 'unknown')} tone={toneForStatus(queue?.status)} />
              </div>
              <p className="mt-2 text-xs text-text-secondary">Jobs {queue?.jobs_total ?? '-'} | Failed {queue?.failed ?? 0}</p>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Models</p>
              <div className="mt-3">
                <StatusPill label={String(models?.status || 'unknown')} tone={toneForStatus(models?.status)} />
              </div>
              <p className="mt-2 text-xs text-text-secondary">Missing domains {(models?.missing_active_domains || []).join(', ') || 'None'}</p>
            </div>
          </div>

          {(health?.issues?.length || health?.warnings?.length) ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-red-200">Issues</p>
                <ul className="mt-2 space-y-1 text-sm text-red-100">
                  {(health?.issues || []).length === 0 ? <li>None</li> : (health?.issues || []).map((item) => <li key={item}>- {item}</li>)}
                </ul>
              </div>
              <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-amber-200">Warnings</p>
                <ul className="mt-2 space-y-1 text-sm text-amber-100">
                  {(health?.warnings || []).length === 0 ? <li>None</li> : (health?.warnings || []).map((item) => <li key={item}>- {item}</li>)}
                </ul>
              </div>
            </div>
          ) : null}
        </Surface>

        <Surface title="Endpoint telemetry" description="Slowest and most error-prone HTTP endpoints from backend telemetry.">
          <div className="overflow-hidden rounded-2xl border border-border-dark/70">
            <table className="min-w-full divide-y divide-border-dark/70 text-sm">
              <thead className="bg-dark-tertiary/90 text-text-secondary">
                <tr>
                  <th className="px-4 py-3 text-left font-medium">Endpoint</th>
                  <th className="px-4 py-3 text-left font-medium">Requests</th>
                  <th className="px-4 py-3 text-left font-medium">Avg latency</th>
                  <th className="px-4 py-3 text-left font-medium">Errors</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60 bg-[#0d1729]/60">
                {endpointRows.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-text-secondary">
                      No endpoint telemetry available yet.
                    </td>
                  </tr>
                ) : (
                  endpointRows.map((item, index) => (
                    <tr key={`${item.method || 'ANY'}:${item.path || 'path'}:${index}`}>
                      <td className="px-4 py-3 text-white">{item.method ? `${item.method} ` : ''}{item.path || 'Unknown'}</td>
                      <td className="px-4 py-3 text-text-secondary">{item.requests_total ?? '-'}</td>
                      <td className="px-4 py-3 text-text-secondary">{Math.round(Number(item.latency_ms_avg || 0))} ms</td>
                      <td className="px-4 py-3 text-text-secondary">{item.errors_total ?? '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Surface title="False-positive trend" description="Human-labeled false positives from analyst feedback.">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={fpSeries}>
                <CartesianGrid stroke="#253044" strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="#8B949E" />
                <Tooltip contentStyle={{ backgroundColor: '#0e1727', border: '1px solid #30363D', borderRadius: 16 }} />
                <Line type="monotone" dataKey="sql" stroke="#22d3ee" strokeWidth={2} />
                <Line type="monotone" dataKey="spam" stroke="#f59e0b" strokeWidth={2} />
                <Line type="monotone" dataKey="file" stroke="#ef4444" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Surface>

        <Surface title="Websocket health" description="Realtime channel counters and broadcast reliability.">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={[
                  { name: 'Active', value: websocket?.active_connections ?? 0 },
                  { name: 'Total Conn', value: websocket?.connections_total ?? 0 },
                  { name: 'Broadcasted', value: websocket?.messages_broadcast_total ?? 0 },
                  { name: 'Failures', value: websocket?.broadcast_send_failures_total ?? 0 },
                ]}
              >
                <CartesianGrid stroke="#253044" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="#8B949E" />
                <Tooltip contentStyle={{ backgroundColor: '#0e1727', border: '1px solid #30363D', borderRadius: 16 }} />
                <Bar dataKey="value" fill="#22d3ee" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Surface>
      </div>
    </div>
  );
};

export default PlatformHealthPage;
