import * as React from 'react';
import SpamAnalyzerPage from '../spam_analyzer/SpamAnalyzerPage';
import { getDashboardSpamDetections, getDashboardStats, getLiveEvents } from '../../lib/apiClient';
import { EmptyState, ErrorState, LoadingState, Surface, StatTile, StatusPill } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import type { DashboardSpamDetectionItem } from '../../types/api';

type EmailRowView = {
  id: string;
  subject: string;
  timestamp: string;
  classification: string;
  status: string;
  tone: 'danger' | 'warning' | 'success' | 'info';
};

const EmailSecurityPage = ({ role }: { role: string }) => {
  const canReadDetail = role === 'analyst' || role === 'admin';
  const [stats, setStats] = React.useState<any>(null);
  const [detections, setDetections] = React.useState<EmailRowView[]>([]);
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
          const spamRes = await getDashboardSpamDetections(today, false, { page: 1, page_size: 8 });
          const rows = (spamRes.data.detections || []).map((row: DashboardSpamDetectionItem): EmailRowView => ({
            id: row.analysis_id,
            subject: row.received_subject || 'Untitled message',
            timestamp: row.timestamp,
            classification:
              row.classification_label ||
              (row.category === 'blocked'
                ? 'Phishing'
                : row.category === 'suspicious'
                  ? 'Needs Review'
                  : row.is_spam
                    ? 'Suspicious'
                    : 'Ham'),
            status: row.category || 'Review',
            tone: row.category === 'blocked' ? 'danger' : row.category === 'suspicious' || row.is_spam ? 'warning' : 'success',
          }));
          setDetections(rows);
          return;
        }

        const viewerFeed = await getLiveEvents(80, { event_types: 'spam_check' });
        const rows = (viewerFeed.data.events || [])
          .filter((event: any) => String(event.type || '').toLowerCase() === 'spam_check')
          .slice(0, 8)
          .map((event: any): EmailRowView => ({
            id: String(event.id || `${event.timestamp || ''}:${event.message || ''}`),
            subject: String(event.message || 'Email security event'),
            timestamp: String(event.timestamp || new Date().toISOString()),
            classification: event.isMalicious ? 'Suspicious' : 'Observed',
            status: event.isMalicious ? 'Needs review' : 'Observed',
            tone: event.isMalicious ? 'warning' : 'info',
          }));
        setDetections(rows);
      } catch {
        setDetections([]);
        setErrorText('Unable to load email event list for this role.');
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [canReadDetail, today]);

  const suspiciousCount = detections.filter((item) => item.tone === 'danger' || item.tone === 'warning').length;

  return (
    <div className="space-y-6">
      {errorText ? (
        <ErrorState message={errorText} />
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <StatTile
          label="Spam flagged"
          value={stats?.spam_detected ?? '-'}
          tone={(stats?.spam_detected || 0) > 0 ? 'warning' : 'success'}
          meta="Detected by current model stack"
        />
        <StatTile label="Recent detections" value={detections.length} tone="info" meta="Visible in active window" />
        <StatTile
          label="Model posture"
          value={suspiciousCount > 0 ? 'Watch' : 'Quiet'}
          tone={suspiciousCount > 0 ? 'warning' : 'success'}
          meta={canReadDetail ? 'Operational summary' : 'Viewer summary mode'}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <Surface
          title="Recent email events"
          description={
            canReadDetail
              ? 'Recent spam/phishing classifications and analyst review candidates.'
              : 'Viewer-safe email activity stream (no privileged detail payloads).'
          }
        >
          <div className="space-y-3">
            {loading ? (
              <LoadingState label="Loading email events..." />
            ) : detections.length === 0 ? (
              <EmptyState title="No email events" description="No email events available in the current window." />
            ) : (
              detections.map((row) => (
                <div key={row.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{row.subject}</p>
                      <p className="mt-1 text-xs text-text-secondary">{formatTimestamp(row.timestamp)}</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <StatusPill label={row.classification} tone={row.tone} />
                      <StatusPill label={row.status} tone={row.tone === 'danger' ? 'danger' : 'info'} />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface title="Analysis studio" description="Use the existing email analysis workflow inside the new console shell.">
          <SpamAnalyzerPage />
        </Surface>
      </div>
    </div>
  );
};

export default EmailSecurityPage;
