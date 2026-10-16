import * as React from 'react';
import {
  createCase,
  createCaseFromAlert,
  getAlertDetails,
  getInvestigationTimeline,
  getLiveEventDetail,
} from '../../lib/apiClient';
import { useAppStore } from '../../store/appStore';
import { useNotification } from '../../contexts/useNotification';
import { ActionButton, Surface, StatusPill, EmptyState, ErrorState, LoadingState } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import { userDisplayMeta, userDisplayName } from '../../lib/userDisplay';
import type { InvestigationTimelineItem } from '../../types/api';

type DetailPayload = {
  id: string;
  type: string;
  timestamp?: string | null;
  summary?: string | null;
  isMalicious?: boolean;
  details?: Record<string, any> | null;
};

const severityTone = (severity: string | null | undefined) => {
  const value = String(severity || '').toLowerCase();
  if (value.includes('critical') || value.includes('high') || value.includes('block')) return 'danger';
  if (value.includes('medium') || value.includes('suspicious') || value.includes('warn')) return 'warning';
  return 'info';
};

const correlationTone = (level: string | null | undefined) => {
  const value = String(level || '').toLowerCase();
  if (value === 'strong') return 'danger';
  if (value === 'moderate') return 'warning';
  if (value === 'weak') return 'info';
  return 'neutral';
};

const domainForEventType = (eventType: string): string => {
  if (eventType === 'query') return 'sql';
  if (eventType === 'file_scan') return 'file';
  if (eventType === 'spam_check') return 'spam';
  return 'alert';
};

const sourceIdFromTimelineItem = (item: InvestigationTimelineItem | null): string => {
  if (!item) return '';
  return String(item.source_ref?.id || '').trim();
};

const entityPairs = (item: InvestigationTimelineItem | null): Array<{ label: string; value: string }> => {
  if (!item) return [];
  const rows: Array<{ label: string; value: string }> = [];
  const mapping = item.entity_keys || {};
  Object.entries(mapping).forEach(([key, value]) => {
    const text = String(value || '').trim();
    if (!text) return;
    rows.push({ label: key, value: text });
  });
  return rows.slice(0, 16);
};

const InvestigationPage = ({ role }: { role: string }) => {
  const privileged = role === 'analyst' || role === 'admin';
  const { showNotification } = useNotification();
  const { globalTimeRange, setActivePage } = useAppStore();

  const [timeline, setTimeline] = React.useState<InvestigationTimelineItem[]>([]);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [focusedAlertId, setFocusedAlertId] = React.useState<string | null>(null);
  const [loadingTimeline, setLoadingTimeline] = React.useState(false);
  const [timelineError, setTimelineError] = React.useState('');

  const [detailLoading, setDetailLoading] = React.useState(false);
  const [detailError, setDetailError] = React.useState('');
  const [selectedDetail, setSelectedDetail] = React.useState<DetailPayload | null>(null);

  const [caseBusy, setCaseBusy] = React.useState(false);
  const [createdCaseId, setCreatedCaseId] = React.useState<string | null>(null);

  const loadTimeline = React.useCallback(async () => {
    if (!privileged) return;
    setLoadingTimeline(true);
    setTimelineError('');
    try {
      const now = new Date();
      const params: Record<string, any> = {
        event_types: 'query,file_scan,spam_check,alert,case,case_note,case_alert_link',
      };
      if (globalTimeRange === '24h') {
        params.start = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
        params.limit = 180;
      } else if (globalTimeRange === '7d') {
        params.start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
        params.limit = 260;
      } else if (globalTimeRange === '30d') {
        params.start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
        params.limit = 320;
      } else {
        params.limit = 360;
      }
      const res = await getInvestigationTimeline(params);
      let items = res.data?.items || [];
      if (focusedAlertId && !items.some((item) => item.event_type === 'alert' && String(item.entity_keys?.alert_id || '') === focusedAlertId)) {
        items = [
          {
            id: `alert:${focusedAlertId}`,
            timestamp: new Date().toISOString(),
            event_type: 'alert',
            severity: 'High',
            title: `Alert ${focusedAlertId}`,
            summary: 'Focused from Alerts workspace.',
            entity_keys: { alert_id: focusedAlertId },
            source_ref: { type: 'alert', id: focusedAlertId },
            case_ids: [],
          },
          ...items,
        ];
      }
      setTimeline(items);
    } catch (error: any) {
      setTimelineError(String(error?.response?.data?.detail || 'Failed to load investigation timeline.'));
      setTimeline([]);
    } finally {
      setLoadingTimeline(false);
    }
  }, [focusedAlertId, globalTimeRange, privileged]);

  React.useEffect(() => {
    void loadTimeline();
    if (!privileged) return;
    const timerId = window.setInterval(() => {
      void loadTimeline();
    }, 30000);
    return () => window.clearInterval(timerId);
  }, [loadTimeline, privileged]);

  React.useEffect(() => {
    const onFocusInvestigation = (event: Event) => {
      const custom = event as CustomEvent<{ alertId?: string }>;
      const alertId = String(custom.detail?.alertId || '').trim();
      if (!alertId) return;
      setFocusedAlertId(alertId);
      setSelectedId(`alert:${alertId}`);
    };
    window.addEventListener('investigation:focus', onFocusInvestigation as EventListener);
    return () => window.removeEventListener('investigation:focus', onFocusInvestigation as EventListener);
  }, []);

  React.useEffect(() => {
    if (timeline.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !timeline.some((item) => item.id === selectedId)) {
      setSelectedId(timeline[0].id);
    }
  }, [selectedId, timeline]);

  const selectedItem = React.useMemo(
    () => timeline.find((item) => item.id === selectedId) || null,
    [selectedId, timeline]
  );

  React.useEffect(() => {
    let cancelled = false;
    const loadSelectedDetail = async () => {
      if (!selectedItem) {
        setSelectedDetail(null);
        setDetailError('');
        return;
      }
      setCreatedCaseId(null);
      setDetailLoading(true);
      setDetailError('');
      try {
        const sourceId = sourceIdFromTimelineItem(selectedItem);
        if (selectedItem.event_type === 'alert') {
          const alertId = sourceId || String(selectedItem.entity_keys?.alert_id || '').trim();
          if (alertId) {
            const alertRes = await getAlertDetails(alertId);
            if (cancelled) return;
            const alertDetail = alertRes.data;
            setSelectedDetail({
              id: alertDetail.id,
              type: 'alert',
              timestamp: alertDetail.timestamp,
              summary: alertDetail.title || alertDetail.message || 'Alert detail',
              isMalicious: true,
              details: alertDetail as unknown as Record<string, any>,
            });
            return;
          }
        }

        if (selectedItem.event_type === 'query' || selectedItem.event_type === 'file_scan' || selectedItem.event_type === 'spam_check') {
          const liveDetailRes = await getLiveEventDetail(selectedItem.event_type as any, sourceId);
          if (cancelled) return;
          setSelectedDetail({
            id: String(liveDetailRes.data?.id || selectedItem.id),
            type: String(liveDetailRes.data?.type || selectedItem.event_type),
            timestamp: liveDetailRes.data?.timestamp || selectedItem.timestamp,
            summary: liveDetailRes.data?.summary || selectedItem.title,
            isMalicious: Boolean(liveDetailRes.data?.isMalicious),
            details: liveDetailRes.data?.details || null,
          });
          return;
        }

        setSelectedDetail({
          id: selectedItem.id,
          type: selectedItem.event_type,
          timestamp: selectedItem.timestamp,
          summary: selectedItem.title,
          isMalicious: false,
          details: {
            summary: selectedItem.summary,
            entity_keys: selectedItem.entity_keys,
            source_ref: selectedItem.source_ref,
            case_ids: selectedItem.case_ids,
          },
        });
      } catch (error: any) {
        if (cancelled) return;
        setSelectedDetail(null);
        setDetailError(String(error?.response?.data?.detail || 'Failed to load timeline detail.'));
      } finally {
        if (!cancelled) setDetailLoading(false);
      }
    };
    void loadSelectedDetail();
    return () => {
      cancelled = true;
    };
  }, [selectedItem]);

  const linkedEntities = React.useMemo(() => {
    if (!selectedItem) return [];
    const backendEntities =
      (selectedItem.related_entities || [])
        .map((entity) => ({
          label: entity.key,
          value: `${entity.value} (${entity.match_count})`,
        }))
        .slice(0, 12);
    if (backendEntities.length > 0) return backendEntities;
    return entityPairs(selectedItem);
  }, [selectedItem]);

  const relatedEvents = React.useMemo(() => {
    if (!selectedItem) return [];
    if ((selectedItem.related_events || []).length > 0) {
      return (selectedItem.related_events || []).slice(0, 8);
    }
    const relatedCaseIds = new Set((selectedItem.case_ids || []).map((value) => String(value)));
    return timeline
      .filter((item) => {
        if (item.id === selectedItem.id) return false;
        if (item.event_type === selectedItem.event_type) return true;
        if (relatedCaseIds.size === 0) return false;
        return (item.case_ids || []).some((caseId) => relatedCaseIds.has(String(caseId)));
      })
      .slice(0, 8);
  }, [selectedItem, timeline]);

  const openFirstCase = React.useCallback(() => {
    if (!selectedItem?.case_ids?.length) return;
    const caseId = String(selectedItem.case_ids[0] || '').trim();
    if (!caseId) return;
    try {
      window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId } }));
    } catch {
      // no-op
    }
    setActivePage('cases');
  }, [selectedItem, setActivePage]);

  const createCaseFromSelection = React.useCallback(async () => {
    if (!selectedItem || caseBusy) return;
    setCaseBusy(true);
    try {
      const sourceId = sourceIdFromTimelineItem(selectedItem);
      if (selectedItem.event_type === 'alert') {
        const alertId = sourceId || String(selectedItem.entity_keys?.alert_id || '').trim();
        const created = await createCaseFromAlert(alertId);
        const caseId = String(created.data?.id || '').trim();
        setCreatedCaseId(caseId || null);
        showNotification(caseId ? `Case created: ${caseId}` : 'Case created from alert.', 'success');
        return;
      }

      if (selectedItem.event_type === 'case' || selectedItem.event_type === 'case_note' || selectedItem.event_type === 'case_alert_link') {
        openFirstCase();
        return;
      }

      let detailText = '';
      try {
        detailText = JSON.stringify(selectedDetail?.details || {}, null, 2);
      } catch {
        detailText = '{}';
      }
      let description = [
        `Summary: ${selectedDetail?.summary || selectedItem.summary || selectedItem.title}`,
        `Event type: ${selectedItem.event_type}`,
        `Source id: ${sourceId}`,
        `Observed: ${selectedItem.timestamp}`,
        `Details:\n${detailText}`,
      ].join('\n');
      if (description.length > 3800) {
        description = `${description.slice(0, 3800)}\n...[truncated]`;
      }

      const created = await createCase({
        title: `Investigate ${selectedItem.event_type.replace('_', ' ')} event`,
        description,
        severity: selectedDetail?.isMalicious ? 'High' : 'Medium',
        domain: domainForEventType(selectedItem.event_type),
        source_type: selectedItem.event_type,
        source_id: sourceId,
        tags: ['from-investigation'],
        evidence: [
          {
            type: 'investigation_event',
            event_type: selectedItem.event_type,
            source_id: sourceId,
            summary: selectedItem.summary,
            details: selectedDetail?.details || null,
          },
        ],
      });
      const caseId = String(created.data?.id || '').trim();
      setCreatedCaseId(caseId || null);
      showNotification(caseId ? `Case created: ${caseId}` : 'Case created.', 'success');
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to create case from selected item.'), 'error');
    } finally {
      setCaseBusy(false);
    }
  }, [caseBusy, openFirstCase, selectedDetail, selectedItem, showNotification]);

  if (!privileged) {
    return <EmptyState title="Investigation workspace restricted" description="Cross-domain investigation is limited to analyst and admin roles." />;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
      <Surface
        title="Investigation timeline"
        description="Backend-aggregated timeline across alerts, analyses, cases, notes, and alert links."
        actions={
          <ActionButton
            onClick={() => void loadTimeline()}
            disabled={loadingTimeline}
            variant="primary"
          >
            {loadingTimeline ? 'Refreshing...' : 'Refresh'}
          </ActionButton>
        }
      >
        {timelineError ? (
          <ErrorState message={timelineError} onRetry={() => void loadTimeline()} />
        ) : null}
        {loadingTimeline ? (
          <LoadingState label="Loading investigation timeline..." />
        ) : timeline.length === 0 ? (
          <EmptyState title="No timeline items yet" description="Waiting for aggregated events from backend investigation service." />
        ) : (
          <div className="space-y-3">
            {timeline.map((item) => (
              <button
                key={item.id}
                onClick={() => setSelectedId(item.id)}
                className={`w-full rounded-2xl border p-4 text-left transition ${
                  selectedItem?.id === item.id
                    ? 'border-cyan-400/40 bg-cyan-500/10'
                    : 'border-border-dark/70 bg-dark-tertiary/70 hover:bg-dark-tertiary'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusPill label={item.event_type.replace(/_/g, ' ')} tone={item.event_type === 'alert' ? 'danger' : 'info'} />
                      <StatusPill label={String(item.severity || 'info').toUpperCase()} tone={severityTone(item.severity)} />
                      {item.correlation_level && item.correlation_level !== 'none' ? (
                        <StatusPill
                          label={`Correlation ${String(item.correlation_level).toUpperCase()}`}
                          tone={correlationTone(item.correlation_level)}
                        />
                      ) : null}
                      {item.case_ids?.length ? (
                        <StatusPill label={`${item.case_ids.length} linked case${item.case_ids.length > 1 ? 's' : ''}`} tone="neutral" />
                      ) : null}
                    </div>
                    <p className="mt-2 text-sm text-white">{item.title}</p>
                    {item.summary ? <p className="mt-1 text-xs text-text-secondary">{item.summary}</p> : null}
                    {(item.actor || item.actor_user_id || item.owner || item.owner_user_id) ? (
                      <p className="mt-1 text-xs text-text-secondary">
                        {item.actor || item.actor_user_id
                          ? `Actor: ${userDisplayName(item.actor, item.actor_user_id, 'system')}`
                          : null}
                        {(item.actor || item.actor_user_id) && (item.owner || item.owner_user_id) ? ' - ' : ''}
                        {item.owner || item.owner_user_id
                          ? `Owner: ${userDisplayName(item.owner, item.owner_user_id, 'unassigned')}`
                          : null}
                      </p>
                    ) : null}
                  </div>
                  <span className="text-xs text-text-secondary">{formatTimestamp(item.timestamp)}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </Surface>

      <Surface title="Evidence pane" description="Detailed evidence and one-click case triage for selected investigation item.">
        {detailLoading ? (
          <LoadingState label="Fetching detailed payload for selected timeline item..." />
        ) : detailError ? (
          <ErrorState message={detailError} onRetry={() => void loadTimeline()} />
        ) : selectedItem && selectedDetail ? (
          <div className="space-y-4">
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusPill label={selectedDetail.type.replace(/_/g, ' ')} tone={selectedDetail.type === 'alert' ? 'danger' : 'info'} />
                <StatusPill label={selectedDetail.isMalicious ? 'High risk' : 'Review'} tone={selectedDetail.isMalicious ? 'danger' : 'warning'} />
                {selectedItem.correlation_level && selectedItem.correlation_level !== 'none' ? (
                  <StatusPill
                    label={`Correlation ${String(selectedItem.correlation_level).toUpperCase()}`}
                    tone={correlationTone(selectedItem.correlation_level)}
                  />
                ) : null}
              </div>
              <p className="mt-3 text-lg font-semibold text-white">{selectedDetail.summary || selectedItem.title}</p>
              <p className="mt-2 text-sm text-text-secondary">Observed {formatTimestamp(selectedDetail.timestamp || selectedItem.timestamp)}</p>
              {(selectedItem.actor || selectedItem.actor_user_id || selectedItem.owner || selectedItem.owner_user_id) ? (
                <p className="mt-1 text-sm text-text-secondary">
                  {selectedItem.actor || selectedItem.actor_user_id ? (
                    (() => {
                      const meta = userDisplayMeta(selectedItem.actor, selectedItem.actor_user_id);
                      return `Actor: ${userDisplayName(selectedItem.actor, selectedItem.actor_user_id, 'system')}${meta ? ` (${meta})` : ''}`;
                    })()
                  ) : null}
                  {(selectedItem.actor || selectedItem.actor_user_id) && (selectedItem.owner || selectedItem.owner_user_id) ? ' - ' : ''}
                  {selectedItem.owner || selectedItem.owner_user_id ? (
                    (() => {
                      const meta = userDisplayMeta(selectedItem.owner, selectedItem.owner_user_id);
                      return `Owner: ${userDisplayName(selectedItem.owner, selectedItem.owner_user_id, 'unassigned')}${meta ? ` (${meta})` : ''}`;
                    })()
                  ) : null}
                </p>
              ) : null}
              {(selectedItem.correlation_reasons || []).length > 0 ? (
                <div className="mt-2 rounded-xl border border-border-dark/70 bg-[#09111f] p-3">
                  <p className="text-[11px] uppercase tracking-[0.14em] text-text-secondary">Why Related</p>
                  <div className="mt-2 space-y-1">
                    {(selectedItem.correlation_reasons || []).slice(0, 5).map((reason) => (
                      <p key={`${reason.code}:${reason.key || ''}:${reason.value || ''}`} className="text-xs text-cyan-200">
                        {reason.label}
                        {reason.key && reason.value ? ` (${reason.key}: ${reason.value})` : ''}
                        {reason.detail ? ` - ${reason.detail}` : ''}
                      </p>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Actions</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <ActionButton
                  onClick={() => void createCaseFromSelection()}
                  disabled={caseBusy}
                  variant="primary"
                >
                  {caseBusy ? 'Working...' : selectedItem.event_type.startsWith('case') ? 'Open linked case' : 'Create case'}
                </ActionButton>
                {createdCaseId ? (
                  <ActionButton
                    onClick={() => {
                      try {
                        window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId: createdCaseId } }));
                      } catch {
                        // no-op
                      }
                      setActivePage('cases');
                    }}
                    variant="secondary"
                  >
                    Open case {createdCaseId}
                  </ActionButton>
                ) : null}
                {selectedItem.case_ids?.length ? (
                  <ActionButton
                    onClick={openFirstCase}
                    variant="secondary"
                  >
                    Open linked case
                  </ActionButton>
                ) : null}
                {selectedItem.event_type === 'alert' ? (
                  <ActionButton
                    onClick={() => {
                      const alertId = sourceIdFromTimelineItem(selectedItem) || String(selectedItem.entity_keys?.alert_id || '').trim();
                      try {
                        window.dispatchEvent(new CustomEvent('alerts:focus', { detail: { alertId } }));
                      } catch {
                        // no-op
                      }
                      setActivePage('alerts');
                    }}
                    variant="ghost"
                  >
                    Open in alerts
                  </ActionButton>
                ) : null}
              </div>
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Linked entities</p>
              {linkedEntities.length === 0 ? (
                <p className="mt-3 text-sm text-text-secondary">No structured entities were returned for this item.</p>
              ) : (
                <div className="mt-3 flex flex-wrap gap-2">
                  {linkedEntities.map((entity) => (
                    <StatusPill key={`${entity.label}:${entity.value}`} label={`${entity.label}: ${entity.value}`} tone="info" />
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Related timeline items</p>
              {relatedEvents.length === 0 ? (
                <p className="mt-3 text-sm text-text-secondary">No related events found in current window.</p>
              ) : (
                <div className="mt-3 space-y-2">
                  {relatedEvents.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setSelectedId(item.id)}
                      className="w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-left text-sm text-white hover:border-cyan-400/40"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="truncate">{item.title}</span>
                            {'correlation_level' in item && item.correlation_level ? (
                              <StatusPill
                                label={String(item.correlation_level).toUpperCase()}
                                tone={correlationTone(item.correlation_level)}
                              />
                            ) : null}
                          </div>
                          {'correlation_reasons' in item && Array.isArray(item.correlation_reasons) && item.correlation_reasons.length > 0 ? (
                            <p className="mt-1 truncate text-xs text-cyan-200">
                              {item.correlation_reasons
                                .slice(0, 2)
                                .map((reason) => reason.label)
                                .join(' | ')}
                            </p>
                          ) : null}
                        </div>
                        <span className="shrink-0 text-xs text-text-secondary">{formatTimestamp(item.timestamp)}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-[#09111f] p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Raw detail payload</p>
              <pre className="mt-3 max-h-[260px] overflow-auto whitespace-pre-wrap break-words text-xs text-cyan-200">
                {JSON.stringify(selectedDetail.details || {}, null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <EmptyState title="No correlated item selected" description="Choose a timeline item to review backend evidence and actions." />
        )}
      </Surface>
    </div>
  );
};

export default InvestigationPage;
