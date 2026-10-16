import * as React from 'react';
import QueryAnalyzerPage from '../sql_analyzer/QueryAnalyzerPage';
import { getDashboardSQLQueries, getDashboardStats, getLiveEvents } from '../../lib/apiClient';
import { EmptyState, ErrorState, LoadingState, Surface, StatTile, StatusPill } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import type { DashboardSQLQueryItem } from '../../types/api';

type SqlRowView = {
  id: string;
  query: string;
  timestamp: string;
  risk: string;
  action: string;
  tone: 'danger' | 'warning' | 'success' | 'info';
};

const SQLSecurityPage = ({ role }: { role: string }) => {
  const canReadDetail = role === 'analyst' || role === 'admin';
  const [stats, setStats] = React.useState<any>(null);
  const [queries, setQueries] = React.useState<SqlRowView[]>([]);
  const [errorText, setErrorText] = React.useState('');
  const [loading, setLoading] = React.useState(true);
  const today = new Date().toISOString().slice(0, 10);

  React.useEffect(() => {
    const load = async () => {
      setLoading(true);
      setErrorText('');
      try {
        const statsRes = await getDashboardStats('today');
        setStats(statsRes.data);
      } catch {
        setStats(null);
      }

      try {
        if (canReadDetail) {
          const queriesRes = await getDashboardSQLQueries(today, false, { page: 1, page_size: 8 });
          const rows = (queriesRes.data.queries || []).map((row: DashboardSQLQueryItem): SqlRowView => ({
            id: row.analysis_id,
            query: row.query_received,
            timestamp: row.timestamp,
            risk: row.risk_level || row.classification_label || 'Unknown',
            action: row.suggested_action || 'Review',
            tone: String(row.risk_level || '').toLowerCase().includes('high')
              ? 'danger'
              : row.is_malicious
                ? 'warning'
                : 'success',
          }));
          setQueries(rows);
          return;
        }

        const viewerFeed = await getLiveEvents(80, { event_types: 'query' });
        const rows = (viewerFeed.data.events || [])
          .filter((event: any) => String(event.type || '').toLowerCase() === 'query')
          .slice(0, 8)
          .map((event: any): SqlRowView => ({
            id: String(event.id || `${event.timestamp || ''}:${event.message || ''}`),
            query: String(event.message || 'SQL query event'),
            timestamp: String(event.timestamp || new Date().toISOString()),
            risk: event.isMalicious ? 'Suspicious' : 'Observed',
            action: 'Use analyzer for full evidence',
            tone: event.isMalicious ? 'warning' : 'info',
          }));
        setQueries(rows);
      } catch {
        setQueries([]);
        setErrorText('Unable to load SQL event list for this role.');
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [canReadDetail, today]);

  const suspiciousCount = queries.filter((item) => item.tone === 'danger' || item.tone === 'warning').length;

  return (
    <div className="space-y-6">
      {errorText ? (
        <ErrorState message={errorText} />
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <StatTile label="Queries observed" value={stats?.total_queries ?? '-'} tone="info" meta="Runtime visibility" />
        <StatTile
          label="Malicious flagged"
          value={stats?.malicious_queries ?? '-'}
          tone={(stats?.malicious_queries || 0) > 0 ? 'danger' : 'success'}
          meta="Combined detector output"
        />
        <StatTile
          label="Current stance"
          value={suspiciousCount > 0 ? 'Investigate' : 'Stable'}
          tone={suspiciousCount > 0 ? 'warning' : 'success'}
          meta={canReadDetail ? 'Operational interpretation' : 'Viewer summary mode'}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <Surface
          title="Recent SQL events"
          description={
            canReadDetail
              ? 'Most recent SQL analyses from the dashboard backend.'
              : 'Viewer-safe SQL activity stream (no privileged detail payloads).'
          }
        >
          <div className="space-y-3">
            {loading ? (
              <LoadingState label="Loading SQL events..." />
            ) : queries.length === 0 ? (
              <EmptyState title="No SQL events" description="No SQL events available in the current window." />
            ) : (
              queries.map((row) => (
                <div key={row.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="pr-4">
                      <p className="text-sm font-medium text-white">{row.query}</p>
                      <p className="mt-1 text-xs text-text-secondary">{formatTimestamp(row.timestamp)}</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <StatusPill label={row.risk} tone={row.tone} />
                      <StatusPill label={row.action} tone="info" />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface title="Analysis studio" description="Use the existing query analysis workflow inside the new console shell.">
          <QueryAnalyzerPage />
        </Surface>
      </div>
    </div>
  );
};

export default SQLSecurityPage;
