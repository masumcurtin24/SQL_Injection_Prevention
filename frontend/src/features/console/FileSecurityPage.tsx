import * as React from 'react';
import FileScannerPage from '../file_scanner/FileScannerPage';
import { getDashboardFilesScanned, getDashboardStats, getLiveEvents } from '../../lib/apiClient';
import { EmptyState, ErrorState, LoadingState, Surface, StatTile, StatusPill } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import type { DashboardFileScanItem } from '../../types/api';

type FileRowView = {
  id: string;
  filename: string;
  timestamp: string;
  status: string;
  action: string;
  tone: 'danger' | 'warning' | 'success' | 'info';
};

const FileSecurityPage = ({ role }: { role: string }) => {
  const canReadDetail = role === 'analyst' || role === 'admin';
  const [stats, setStats] = React.useState<any>(null);
  const [files, setFiles] = React.useState<FileRowView[]>([]);
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
          const filesRes = await getDashboardFilesScanned(today, { page: 1, page_size: 8 });
          const rows = (filesRes.data.files || []).map((row: DashboardFileScanItem): FileRowView => ({
            id: row.analysis_id,
            filename: row.filename,
            timestamp: row.timestamp,
            status: row.overall_status || row.category || 'Unknown',
            action: row.recommended_action || 'Review',
            tone: String(row.overall_status || row.category || '').toLowerCase().includes('block')
              ? 'danger'
              : row.category === 'suspicious'
                ? 'warning'
                : 'success',
          }));
          setFiles(rows);
          return;
        }

        const viewerFeed = await getLiveEvents(80, { event_types: 'file_scan' });
        const rows = (viewerFeed.data.events || [])
          .filter((event: any) => String(event.type || '').toLowerCase() === 'file_scan')
          .slice(0, 8)
          .map((event: any): FileRowView => ({
            id: String(event.id || `${event.timestamp || ''}:${event.message || ''}`),
            filename: String(event.message || 'File scan event'),
            timestamp: String(event.timestamp || new Date().toISOString()),
            status: event.isMalicious ? 'Suspicious' : 'Observed',
            action: 'Open scanner for full analysis',
            tone: event.isMalicious ? 'warning' : 'info',
          }));
        setFiles(rows);
      } catch {
        setFiles([]);
        setErrorText('Unable to load file event list for this role.');
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [canReadDetail, today]);

  const suspiciousCount = files.filter((item) => item.tone === 'danger' || item.tone === 'warning').length;

  return (
    <div className="space-y-6">
      {errorText ? (
        <ErrorState message={errorText} />
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <StatTile label="Files scanned" value={stats?.files_scanned ?? '-'} tone="info" meta="Upload inspection coverage" />
        <StatTile label="Suspicious items" value={suspiciousCount} tone={suspiciousCount > 0 ? 'warning' : 'success'} meta="Requires analyst review" />
        <StatTile
          label="Scanner posture"
          value={files.length > 0 ? 'Active' : 'Idle'}
          tone={files.length > 0 ? 'success' : 'neutral'}
          meta={canReadDetail ? 'Observed in current day window' : 'Viewer summary mode'}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <Surface
          title="Recent file events"
          description={
            canReadDetail
              ? 'Latest scan outcomes and recommended actions.'
              : 'Viewer-safe file activity stream (no privileged detail payloads).'
          }
        >
          <div className="space-y-3">
            {loading ? (
              <LoadingState label="Loading file events..." />
            ) : files.length === 0 ? (
              <EmptyState title="No file events" description="No file events available in the current window." />
            ) : (
              files.map((row) => (
                <div key={row.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{row.filename}</p>
                      <p className="mt-1 text-xs text-text-secondary">{formatTimestamp(row.timestamp)}</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <StatusPill label={row.status} tone={row.tone} />
                      <StatusPill label={row.action} tone="info" />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface title="Analysis studio" description="Use the existing file analysis workflow inside the new console shell.">
          <FileScannerPage />
        </Surface>
      </div>
    </div>
  );
};

export default FileSecurityPage;
