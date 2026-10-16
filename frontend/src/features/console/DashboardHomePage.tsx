import * as React from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  acknowledgeAlert,
  createCaseFromAlert,
  getAlertDetails,
  getAlertsPaged,
  getAuditEvents,
  getCaseStats,
  getDashboardAccessFeed,
  getDashboardExecutiveOverview,
  getDashboardPlatformHealth,
  getDashboardStatsHistory,
  getDefenderModels,
  getDefenderStatus,
  getDefenderTrainingJobs,
  getLiveEvents,
  getMonitoringFalsePositiveTrends,
  getSqlEnforcementConfig,
} from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import { useWebSocket } from '../../contexts/useWebSocket';
import { useAppStore } from '../../store/appStore';
import { EmptyState, ErrorState, LoadingState, StatTile, StatusPill, Surface } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import type {
  Alert,
  AlertDetails,
  DashboardExecutiveOverview,
  DashboardPlatformHealthResponse,
  DashboardStatsDailyPoint,
  DefenderModelInfo,
  DefenderStatusResponse,
  DefenderTrainingJobInfo,
} from '../../types/api';

type UserRole = 'admin' | 'analyst' | 'reviewer' | 'viewer';
type DashboardPageLink =
  | 'alerts'
  | 'cases'
  | 'investigation'
  | 'platformHealth'
  | 'auditLog'
  | 'modelOps'
  | 'policyRules'
  | 'sqlSecurity'
  | 'fileSecurity'
  | 'emailSecurity';

type SummaryCardKey = 'posture' | 'events' | 'suspicious' | 'blocked';

type SummaryMetricDetail = {
  title: string;
  purpose: string;
  equation: string;
  interpretation: string;
  facts: Array<{ label: string; value: string | number }>;
};

const daysFromRange = (range: '24h' | '7d' | '30d' | 'total'): number => {
  if (range === '24h') return 7;
  if (range === '7d') return 14;
  if (range === '30d') return 30;
  return 60;
};

const roleTitle = (role: UserRole): string => {
  if (role === 'admin') return 'Admin';
  if (role === 'analyst') return 'Analyst';
  if (role === 'reviewer') return 'Reviewer / Model Ops';
  return 'Viewer';
};

const toNumber = (value: unknown): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const formatPercent = (value: unknown): string => `${(toNumber(value) * 100).toFixed(1)}%`;

const formatLag = (seconds: unknown): string => {
  const value = toNumber(seconds);
  if (value <= 0) return 'Current';
  if (value < 60) return `${Math.round(value)} sec`;
  if (value < 3600) return `${Math.round(value / 60)} min`;
  return `${Math.round(value / 3600)} hr`;
};

const DashboardHomePage = ({
  role,
  onOpenPage,
}: {
  role: UserRole;
  onOpenPage: (page: DashboardPageLink) => void;
}) => {
  const { showNotification } = useNotification();
  const ws = useWebSocket();
  const globalTimeRange = useAppStore((state) => state.globalTimeRange);

  const [overview, setOverview] = React.useState<DashboardExecutiveOverview | null>(null);
  const [history, setHistory] = React.useState<DashboardStatsDailyPoint[]>([]);
  const [liveEvents, setLiveEvents] = React.useState<any[]>([]);
  const [sharedError, setSharedError] = React.useState('');
  const [sharedLoading, setSharedLoading] = React.useState(true);
  const [activeSummaryCard, setActiveSummaryCard] = React.useState<SummaryCardKey | null>(null);

  const [alerts, setAlerts] = React.useState<Alert[]>([]);
  const [caseStats, setCaseStats] = React.useState<any>(null);
  const [selectedAlertId, setSelectedAlertId] = React.useState('');
  const [selectedAlert, setSelectedAlert] = React.useState<AlertDetails | null>(null);
  const [analystBusy, setAnalystBusy] = React.useState(false);

  const [platformHealth, setPlatformHealth] = React.useState<DashboardPlatformHealthResponse | null>(null);
  const [accessFeed, setAccessFeed] = React.useState<any>(null);
  const [auditItems, setAuditItems] = React.useState<any[]>([]);
  const [sqlPolicy, setSqlPolicy] = React.useState<any>(null);

  const [defenderStatus, setDefenderStatus] = React.useState<DefenderStatusResponse | null>(null);
  const [defenderModels, setDefenderModels] = React.useState<DefenderModelInfo[]>([]);
  const [trainingJobs, setTrainingJobs] = React.useState<DefenderTrainingJobInfo[]>([]);
  const [fpSeries, setFpSeries] = React.useState<any[]>([]);

  const isAnalyst = role === 'analyst' || role === 'admin';
  const isReviewer = role === 'reviewer' || role === 'admin';
  const isAdmin = role === 'admin';
  const windowDays = daysFromRange(globalTimeRange);

  const loadShared = React.useCallback(async () => {
    setSharedLoading(true);
    setSharedError('');
    try {
      const [overviewRes, historyRes, liveRes] = await Promise.all([
        getDashboardExecutiveOverview('today'),
        getDashboardStatsHistory(windowDays),
        getLiveEvents(30, {
          event_types: role === 'viewer' ? 'query,file_scan,spam_check' : 'query,file_scan,spam_check,alert',
        }),
      ]);
      setOverview(overviewRes.data || null);
      setHistory(historyRes.data?.data || []);
      setLiveEvents(liveRes.data?.events || []);
    } catch (error: any) {
      setSharedError(String(error?.response?.data?.detail || 'Failed to load dashboard summary.'));
      setOverview(null);
      setHistory([]);
      setLiveEvents([]);
    } finally {
      setSharedLoading(false);
    }
  }, [role, windowDays]);

  const loadAnalyst = React.useCallback(async () => {
    if (!isAnalyst) return;
    const [alertsRes, caseStatsRes] = await Promise.all([
      getAlertsPaged({ page: 1, page_size: 8, severity: 'All' }),
      getCaseStats(),
    ]);
    const nextAlerts = alertsRes.data?.alerts || [];
    setAlerts(nextAlerts);
    setCaseStats(caseStatsRes.data || null);
    if (!selectedAlertId && nextAlerts.length > 0) {
      setSelectedAlertId(String(nextAlerts[0].backend_id || ''));
    }
  }, [isAnalyst, selectedAlertId]);

  const loadReviewer = React.useCallback(async () => {
    if (!isReviewer) return;
    const [statusRes, modelsRes, jobsRes, fpRes] = await Promise.all([
      getDefenderStatus(),
      getDefenderModels({ limit: 50 }),
      getDefenderTrainingJobs({ limit: 20 }),
      getMonitoringFalsePositiveTrends(Math.max(14, windowDays), true),
    ]);
    setDefenderStatus(statusRes.data || null);
    setDefenderModels(modelsRes.data || []);
    setTrainingJobs(jobsRes.data || []);
    setFpSeries(fpRes.data?.series || []);
  }, [isReviewer, windowDays]);

  const loadAdmin = React.useCallback(async () => {
    if (!isAdmin) return;
    const [platformRes, accessRes, auditRes, sqlRes] = await Promise.all([
      getDashboardPlatformHealth(20, windowDays, true),
      getDashboardAccessFeed(10, true),
      getAuditEvents({ limit: 8, offset: 0 }),
      getSqlEnforcementConfig(),
    ]);
    setPlatformHealth(platformRes.data || null);
    setAccessFeed(accessRes.data || null);
    setAuditItems(auditRes.data?.items || []);
    setSqlPolicy(sqlRes.data || null);
  }, [isAdmin, windowDays]);

  React.useEffect(() => {
    void loadShared();
  }, [loadShared]);

  React.useEffect(() => {
    void loadAnalyst();
  }, [loadAnalyst]);

  React.useEffect(() => {
    void loadReviewer();
  }, [loadReviewer]);

  React.useEffect(() => {
    void loadAdmin();
  }, [loadAdmin]);

  React.useEffect(() => {
    const loadDetail = async () => {
      if (!isAnalyst || !selectedAlertId) {
        setSelectedAlert(null);
        return;
      }
      try {
        const response = await getAlertDetails(selectedAlertId);
        setSelectedAlert(response.data || null);
      } catch {
        setSelectedAlert(null);
      }
    };
    void loadDetail();
  }, [isAnalyst, selectedAlertId]);

  const activeModels = defenderModels.filter((m) => String(m.stage || '').toLowerCase() === 'active').length;
  const candidateModels = defenderModels.filter((m) => String(m.stage || '').toLowerCase() === 'candidate').length;
  const failedJobs = trainingJobs.filter((m) => String(m.status || '').toLowerCase() === 'failed').length;

  const createCaseFromSelected = React.useCallback(async () => {
    const alertId = String(selectedAlertId || '').trim();
    if (!alertId || analystBusy) return;
    setAnalystBusy(true);
    try {
      const created = await createCaseFromAlert(alertId);
      const caseId = String(created.data?.id || '').trim();
      showNotification(caseId ? `Case ${caseId} created.` : 'Case created from alert.', 'success');
      await loadAnalyst();
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to create case.'), 'error');
    } finally {
      setAnalystBusy(false);
    }
  }, [analystBusy, loadAnalyst, selectedAlertId, showNotification]);

  const acknowledgeSelected = React.useCallback(async () => {
    const alertId = String(selectedAlertId || '').trim();
    if (!alertId || analystBusy) return;
    setAnalystBusy(true);
    try {
      await acknowledgeAlert(alertId, true);
      showNotification('Alert acknowledged.', 'success');
      await loadAnalyst();
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to acknowledge alert.'), 'error');
    } finally {
      setAnalystBusy(false);
    }
  }, [analystBusy, loadAnalyst, selectedAlertId, showNotification]);

  const openInvestigationForSelected = () => {
    const alertId = String(selectedAlertId || '').trim();
    if (!alertId) return;
    try {
      window.dispatchEvent(new CustomEvent('investigation:focus', { detail: { alertId } }));
    } catch {
      // no-op
    }
    onOpenPage('investigation');
  };

  const toggleSummaryCard = (card: SummaryCardKey) => {
    setActiveSummaryCard((current) => (current === card ? null : card));
  };

  const analysisEvents = toNumber(overview?.totals?.analysis_events);
  const totalEvents = toNumber(overview?.totals?.events);
  const suspiciousTotal = toNumber(overview?.totals?.suspicious);
  const blockedTotal = toNumber(overview?.totals?.blocked);
  const alertTotal = toNumber(overview?.totals?.alerts);
  const criticalAlerts = toNumber(overview?.alerts_by_severity?.critical);
  const highAlerts = toNumber(overview?.alerts_by_severity?.high);
  const detectionRate = toNumber(overview?.rates?.detection_rate);
  const blockRate = toNumber(overview?.rates?.block_rate);
  const alertRate = toNumber(overview?.rates?.alert_rate_per_100_events);
  const domainRows = [
    { label: 'SQL', ...overview?.domains?.sql },
    { label: 'Files', ...overview?.domains?.file },
    { label: 'Spam', ...overview?.domains?.spam },
  ].map((row) => ({
    label: row.label,
    total: toNumber(row.total),
    safe: toNumber(row.safe),
    suspicious: toNumber(row.suspicious),
    blocked: toNumber(row.blocked),
  }));
  const summaryDetails: Record<SummaryCardKey, SummaryMetricDetail> = {
    posture: {
      title: 'Posture score details',
      purpose: 'Shows the current security condition of the platform for today. It compresses suspicious activity, blocked activity, and severe alerts into one score so operators can quickly judge whether the environment is stable, under watch, or critical.',
      equation: 'posture_score = clamp(100 - (block_rate * 70) - (detection_rate * 30) - (min(critical_alerts, 10) * 2) - (min(high_alerts, 10) * 1), 0, 100)',
      interpretation: '80-100 is Stable, 60-79 is Watch, and below 60 is Critical. A critical alert or block rate at or above 20% also pushes posture to Critical.',
      facts: [
        { label: 'Current posture', value: overview?.security_posture || 'n/a' },
        { label: 'Posture score', value: overview?.posture_score ?? '-' },
        { label: 'Detection rate', value: formatPercent(detectionRate) },
        { label: 'Block rate', value: formatPercent(blockRate) },
        { label: 'Critical alerts', value: criticalAlerts },
        { label: 'High alerts', value: highAlerts },
      ],
    },
    events: {
      title: 'Events today details',
      purpose: 'Counts all security-relevant records observed today. This gives a quick view of workload volume across analyzers and alert generation.',
      equation: 'events_today = sql_analysis_events + file_scan_events + spam_analysis_events + alerts',
      interpretation: 'High event volume is not automatically bad. It becomes operationally important when suspicious or blocked percentages rise with it.',
      facts: [
        { label: 'Events today', value: totalEvents },
        { label: 'Analysis events', value: analysisEvents },
        { label: 'Alerts', value: alertTotal },
        { label: 'Alert rate', value: `${alertRate.toFixed(2)} per 100 events` },
        { label: 'Latest event', value: overview?.latency?.latest_event_at ? formatTimestamp(String(overview.latency.latest_event_at)) : 'n/a' },
        { label: 'Ingestion lag', value: formatLag(overview?.latency?.ingestion_lag_seconds) },
      ],
    },
    suspicious: {
      title: 'Suspicious activity details',
      purpose: 'Counts events that were not fully safe but did not meet the immediate block threshold. These items usually need analyst review, tuning feedback, or case investigation.',
      equation: 'suspicious_total = suspicious_sql + suspicious_file + suspicious_spam; detection_rate = (suspicious_total + blocked_total) / analysis_events',
      interpretation: 'Suspicious counts are review workload. A rising suspicious rate can mean a real campaign, noisy rules, or threshold drift.',
      facts: [
        { label: 'Suspicious total', value: suspiciousTotal },
        { label: 'SQL suspicious', value: toNumber(overview?.domains?.sql?.suspicious) },
        { label: 'File suspicious', value: toNumber(overview?.domains?.file?.suspicious) },
        { label: 'Spam suspicious', value: toNumber(overview?.domains?.spam?.suspicious) },
        { label: 'Detection rate', value: formatPercent(detectionRate) },
        { label: 'Top risk count', value: overview?.top_risks?.[0]?.count ?? 0 },
      ],
    },
    blocked: {
      title: 'Blocked activity details',
      purpose: 'Counts actions that policy or detection logic prevented from continuing. This is the strongest evidence that the platform actively stopped risky input.',
      equation: 'blocked_total = blocked_sql + blocked_file + blocked_spam; block_rate = blocked_total / analysis_events',
      interpretation: 'Blocked activity should be reviewed for source patterns and false positives. A high block rate lowers posture because it indicates active threat pressure.',
      facts: [
        { label: 'Blocked total', value: blockedTotal },
        { label: 'SQL blocked', value: toNumber(overview?.domains?.sql?.blocked) },
        { label: 'File blocked', value: toNumber(overview?.domains?.file?.blocked) },
        { label: 'Spam blocked', value: toNumber(overview?.domains?.spam?.blocked) },
        { label: 'Block rate', value: formatPercent(blockRate) },
        { label: 'Prevented vs suspicious', value: `${blockedTotal} / ${suspiciousTotal}` },
      ],
    },
  };
  const activeSummaryDetail = activeSummaryCard ? summaryDetails[activeSummaryCard] : null;

  const sharedSummary = (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.16em] text-cyan-300">Role-based home</p>
          <h2 className="mt-1 text-2xl font-semibold text-white">{roleTitle(role)} dashboard</h2>
        </div>
        <div className="flex items-center gap-2">
          <StatusPill
            label={`Realtime ${String(ws?.status || 'disconnected')}`}
            tone={ws?.status === 'connected' ? 'success' : ws?.status === 'connecting' ? 'warning' : 'danger'}
          />
          {overview?.security_posture ? (
            <StatusPill
              label={`Posture ${overview.security_posture}`}
              tone={overview.security_posture === 'critical' ? 'danger' : overview.security_posture === 'watch' ? 'warning' : 'success'}
            />
          ) : null}
        </div>
      </div>

      {sharedError ? (
        <ErrorState message={sharedError} />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Posture score"
          value={overview?.posture_score ?? '-'}
          tone={(overview?.posture_score || 0) >= 80 ? 'success' : (overview?.posture_score || 0) >= 60 ? 'warning' : 'danger'}
          meta="Security posture"
          onClick={() => toggleSummaryCard('posture')}
          selected={activeSummaryCard === 'posture'}
          ariaLabel="Show posture score details"
        />
        <StatTile
          label="Events today"
          value={overview?.totals?.events ?? '-'}
          tone="info"
          meta="Observed events"
          onClick={() => toggleSummaryCard('events')}
          selected={activeSummaryCard === 'events'}
          ariaLabel="Show events today details"
        />
        <StatTile
          label="Suspicious"
          value={overview?.totals?.suspicious ?? '-'}
          tone={(overview?.totals?.suspicious || 0) > 0 ? 'warning' : 'success'}
          meta="Needs review"
          onClick={() => toggleSummaryCard('suspicious')}
          selected={activeSummaryCard === 'suspicious'}
          ariaLabel="Show suspicious activity details"
        />
        <StatTile
          label="Blocked"
          value={overview?.totals?.blocked ?? '-'}
          tone={(overview?.totals?.blocked || 0) > 0 ? 'danger' : 'success'}
          meta="Prevented actions"
          onClick={() => toggleSummaryCard('blocked')}
          selected={activeSummaryCard === 'blocked'}
          ariaLabel="Show blocked activity details"
        />
      </div>

      {activeSummaryDetail ? (
        <Surface
          title={activeSummaryDetail.title}
          description="Purpose, equation, interpretation, and active dashboard data for the selected card."
          actions={
            <>
              <button
                type="button"
                onClick={() => onOpenPage(activeSummaryCard === 'posture' ? 'platformHealth' : 'investigation')}
                className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-100 transition hover:border-cyan-300/60 hover:bg-cyan-500/20"
              >
                Open related view
              </button>
              <button
                type="button"
                onClick={() => setActiveSummaryCard(null)}
                aria-label="Close selected card details"
                className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white transition hover:border-border-dark hover:bg-dark-tertiary/80"
              >
                Close
              </button>
            </>
          }
        >
          <div className="grid gap-5 xl:grid-cols-[1fr_1.15fr]">
            <div className="space-y-4 text-sm text-text-secondary">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Purpose</h3>
                <p className="mt-2 leading-6">{activeSummaryDetail.purpose}</p>
              </div>
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Equation</h3>
                <p className="mt-2 break-words rounded-xl border border-border-dark/70 bg-[#09111f] p-3 font-mono text-xs leading-5 text-cyan-100">
                  {activeSummaryDetail.equation}
                </p>
              </div>
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">How to read it</h3>
                <p className="mt-2 leading-6">{activeSummaryDetail.interpretation}</p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {activeSummaryDetail.facts.map((fact) => (
                  <div key={fact.label} className="rounded-xl border border-border-dark/70 bg-dark-tertiary/70 p-3">
                    <p className="text-xs uppercase tracking-[0.12em] text-text-muted">{fact.label}</p>
                    <p className="mt-2 break-words text-base font-semibold text-white">{fact.value}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Active domain data</h3>
                  <span className="text-xs text-text-muted">{overview?.as_of ? `As of ${formatTimestamp(String(overview.as_of))}` : 'Waiting for data'}</span>
                </div>
                <div className="overflow-x-auto rounded-xl border border-border-dark/70">
                  <table className="min-w-full divide-y divide-border-dark/70 text-left text-sm">
                    <thead className="bg-dark-tertiary/80 text-xs uppercase tracking-[0.12em] text-text-muted">
                      <tr>
                        <th className="px-3 py-3 font-medium">Domain</th>
                        <th className="px-3 py-3 font-medium">Total</th>
                        <th className="px-3 py-3 font-medium">Safe</th>
                        <th className="px-3 py-3 font-medium">Suspicious</th>
                        <th className="px-3 py-3 font-medium">Blocked</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-dark/60 bg-[#09111f] text-text-secondary">
                      {domainRows.map((row) => (
                        <tr key={row.label}>
                          <td className="px-3 py-3 font-medium text-white">{row.label}</td>
                          <td className="px-3 py-3">{row.total}</td>
                          <td className="px-3 py-3 text-emerald-200">{row.safe}</td>
                          <td className="px-3 py-3 text-amber-200">{row.suspicious}</td>
                          <td className="px-3 py-3 text-red-200">{row.blocked}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Top risks</h3>
                  <div className="mt-2 space-y-2">
                    {(overview?.top_risks || []).length > 0 ? (
                      overview?.top_risks?.slice(0, 4).map((risk) => (
                        <div key={risk.label} className="flex items-center justify-between gap-3 rounded-xl border border-border-dark/70 bg-dark-tertiary/70 px-3 py-2 text-sm">
                          <span className="min-w-0 truncate text-text-secondary">{risk.label}</span>
                          <span className="font-semibold text-white">{risk.count}</span>
                        </div>
                      ))
                    ) : (
                      <p className="rounded-xl border border-border-dark/70 bg-dark-tertiary/70 p-3 text-sm text-text-secondary">No risk clusters in the current window.</p>
                    )}
                  </div>
                </div>
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Recent events</h3>
                  <div className="mt-2 space-y-2">
                    {liveEvents.slice(0, 4).length > 0 ? (
                      liveEvents.slice(0, 4).map((event) => (
                        <div key={`${event.type}:${event.id}`} className="rounded-xl border border-border-dark/70 bg-dark-tertiary/70 px-3 py-2 text-sm text-text-secondary">
                          <p className="truncate text-white">{event.message || event.type || 'Event'}</p>
                          <p className="mt-1 text-xs text-text-muted">{event.timestamp ? formatTimestamp(String(event.timestamp)) : 'Timestamp unavailable'}</p>
                        </div>
                      ))
                    ) : (
                      <p className="rounded-xl border border-border-dark/70 bg-dark-tertiary/70 p-3 text-sm text-text-secondary">No recent events are available in this window.</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Surface>
      ) : null}

      <Surface title="Threat history" description="Cross-window trend for SQL, file, and spam detections.">
        {sharedLoading ? (
          <LoadingState label="Loading posture trend..." />
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <CartesianGrid stroke="#253044" strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="#8B949E" />
                <YAxis stroke="#8B949E" />
                <Tooltip contentStyle={{ backgroundColor: '#0e1727', border: '1px solid #30363D', borderRadius: 16 }} />
                <Line type="monotone" dataKey="malicious_queries" stroke="#ef4444" strokeWidth={2} />
                <Line type="monotone" dataKey="files_scanned" stroke="#22d3ee" strokeWidth={2} />
                <Line type="monotone" dataKey="spam_detected" stroke="#f59e0b" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Surface>
    </div>
  );

  const viewerHome = (
    <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
      <Surface title="Domain summaries" description="Safe, suspicious, and blocked counts by domain.">
        <div className="grid gap-3 md:grid-cols-3">
          {(['sql', 'file', 'spam'] as const).map((domain) => {
            const row = overview?.domains?.[domain];
            return (
              <div key={domain} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">{domain.toUpperCase()}</p>
                <p className="mt-3 text-2xl font-semibold text-white">{row?.total ?? '-'}</p>
                <p className="mt-2 text-xs text-text-secondary">S {row?.safe ?? 0} | Sp {row?.suspicious ?? 0} | B {row?.blocked ?? 0}</p>
              </div>
            );
          })}
        </div>
      </Surface>
      <Surface title="Limited health and activity" description="Viewer-safe summary without privileged controls.">
        <div className="space-y-2">
          <p className="text-sm text-text-secondary">Latest event: {formatTimestamp(String(overview?.latency?.latest_event_at || ''))}</p>
          <p className="text-sm text-text-secondary">Ingestion lag: {overview?.latency?.ingestion_lag_seconds != null ? `${Math.round(Number(overview.latency.ingestion_lag_seconds))} sec` : 'n/a'}</p>
          {liveEvents.slice(0, 6).map((event) => (
            <div key={`${event.type}:${event.id}`} className="rounded-xl border border-border-dark/70 bg-[#09111f] p-2.5 text-sm text-white">
              {event.message}
            </div>
          ))}
        </div>
      </Surface>
    </div>
  );

  const analystHome = (
    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
      <Surface title="Triage queue" description="Alerts ready for acknowledgement, case creation, and investigation.">
        {alerts.length === 0 ? (
          <EmptyState title="No alerts in queue" description="New alerts will appear here for triage." />
        ) : (
          <div className="space-y-2">
            {alerts.map((alert) => {
              const id = String(alert.backend_id || '');
              const selected = selectedAlertId === id;
              return (
                <button
                  key={id || alert.id}
                  type="button"
                  onClick={() => setSelectedAlertId(id)}
                  className={`w-full rounded-xl border p-3 text-left ${selected ? 'border-cyan-400/40 bg-cyan-500/10' : 'border-border-dark/70 bg-dark-tertiary/70'}`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm text-white">{alert.description}</p>
                    <StatusPill label={alert.severity.toUpperCase()} tone={alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'info'} />
                  </div>
                  <p className="mt-1 text-xs text-text-secondary">{formatTimestamp(alert.timestamp)}</p>
                </button>
              );
            })}
          </div>
        )}
      </Surface>
      <Surface title="Evidence and actions" description="Detail panel for fast analyst triage.">
        {selectedAlert ? (
          <div className="space-y-4">
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-sm font-semibold text-white">{selectedAlert.title}</p>
              <p className="mt-2 text-sm text-text-secondary">{selectedAlert.message}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => void acknowledgeSelected()} disabled={analystBusy} className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white disabled:opacity-50">Acknowledge</button>
              <button type="button" onClick={() => void createCaseFromSelected()} disabled={analystBusy} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-200 disabled:opacity-50">Create case</button>
              <button type="button" onClick={openInvestigationForSelected} disabled={analystBusy} className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white disabled:opacity-50">Investigate</button>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-3 text-xs text-text-secondary">
              Open cases: {caseStats?.open_cases ?? 0} | Total cases: {caseStats?.total_cases ?? 0}
            </div>
          </div>
        ) : (
          <EmptyState title="Select an alert" description="Choose an alert from queue to view evidence and actions." />
        )}
      </Surface>
    </div>
  );

  const adminHome = (
    <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
      <Surface title="Platform and policy visibility" description="Control-plane snapshot for admin operations.">
        <div className="space-y-3 text-sm text-text-secondary">
          <p>Health score: <span className="text-white">{platformHealth?.score ?? '-'}</span></p>
          <p>HTTP status: <span className="text-white">{String(platformHealth?.components?.http?.status || 'unknown')}</span></p>
          <p>Queue status: <span className="text-white">{String(platformHealth?.components?.queue?.status || 'unknown')}</span></p>
          <p>SQL ddl policy: <span className="text-white">{String(sqlPolicy?.rules?.ddl_exec?.policy || 'n/a')}</span></p>
          <div className="flex flex-wrap gap-2 pt-2">
            <button type="button" onClick={() => onOpenPage('platformHealth')} className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white">Platform health</button>
            <button type="button" onClick={() => onOpenPage('policyRules')} className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white">Policy & rules</button>
            <button type="button" onClick={() => onOpenPage('auditLog')} className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white">Audit log</button>
          </div>
        </div>
      </Surface>
      <Surface title="Access feed and audit" description="Who is active and what privileged actions occurred.">
        <div className="space-y-2">
          {(accessFeed?.items || []).slice(0, 5).map((item: any) => (
            <div key={item.session_id} className="rounded-xl border border-border-dark/70 bg-[#09111f] p-2.5">
              <p className="text-sm text-white">{item.full_name || item.email}</p>
              <p className="text-xs text-text-secondary">{item.role} | {item.status}</p>
            </div>
          ))}
          {auditItems.slice(0, 4).map((item: any) => (
            <div key={item.id} className="rounded-xl border border-border-dark/70 bg-[#09111f] p-2.5">
              <p className="text-sm text-white">{item.action}</p>
              <p className="text-xs text-text-secondary">{formatTimestamp(item.timestamp)}</p>
            </div>
          ))}
        </div>
      </Surface>
    </div>
  );

  const reviewerHome = (
    <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
      <Surface title="Model health and comparison" description="Active/candidate model counts and feedback backlog.">
        <div className="grid gap-3 md:grid-cols-2">
          <StatTile label="Pending feedback" value={defenderStatus?.pending_feedback ?? '-'} tone={(defenderStatus?.pending_feedback || 0) > 0 ? 'warning' : 'success'} />
          <StatTile label="Active models" value={activeModels} tone={activeModels >= 3 ? 'success' : 'warning'} />
          <StatTile label="Candidate models" value={candidateModels} tone={candidateModels > 0 ? 'info' : 'neutral'} />
          <StatTile label="Failed jobs" value={failedJobs} tone={failedJobs > 0 ? 'danger' : 'success'} />
        </div>
      </Surface>
      <Surface title="Drift and training trends" description="False-positive trend and recent training jobs.">
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={fpSeries}>
              <CartesianGrid stroke="#253044" strokeDasharray="3 3" />
              <XAxis dataKey="date" stroke="#8B949E" />
              <YAxis stroke="#8B949E" />
              <Tooltip contentStyle={{ backgroundColor: '#0e1727', border: '1px solid #30363D', borderRadius: 16 }} />
              <Bar dataKey="sql" fill="#22d3ee" />
              <Bar dataKey="spam" fill="#f59e0b" />
              <Bar dataKey="file" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-3 space-y-1.5">
          {trainingJobs.slice(0, 4).map((job) => (
            <div key={job.id} className="rounded-xl border border-border-dark/70 bg-[#09111f] p-2.5 text-sm text-white">
              {job.domain.toUpperCase()} - {job.status}
            </div>
          ))}
          <button type="button" onClick={() => onOpenPage('modelOps')} className="mt-2 rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white">Open model ops</button>
        </div>
      </Surface>
    </div>
  );

  return (
    <div className="space-y-6">
      {sharedSummary}
      {role === 'viewer' ? viewerHome : null}
      {role === 'analyst' ? analystHome : null}
      {role === 'admin' ? (
        <div className="space-y-6">
          {analystHome}
          {adminHome}
        </div>
      ) : null}
      {role === 'reviewer' ? reviewerHome : null}
    </div>
  );
};

export default DashboardHomePage;
