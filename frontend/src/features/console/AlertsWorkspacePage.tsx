import * as React from 'react';
import {
  acknowledgeAlert,
  assignCaseOwner,
  createCaseFromAlert,
  getAlertDetails,
  getAlertsPaged,
  getAuthUser,
} from '../../lib/apiClient';
import type { Alert, AlertDetails } from '../../types/api';
import { ActionButton, Surface, StatusPill, EmptyState, ErrorState, LoadingState } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import { userDisplayName } from '../../lib/userDisplay';
import { useNotification } from '../../contexts/useNotification';
import { useAppStore } from '../../store/appStore';
import ExplainabilityPanel from '../../components/common/ExplainabilityPanel';

type AlertSeverityFilter = 'All' | 'Critical' | 'High' | 'Medium' | 'Low';

const severityFromGlobal = (value: string): AlertSeverityFilter => {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  return 'All';
};

const makeSyntheticAlert = (alertId: string): Alert => ({
  id: Date.now(),
  backend_id: alertId,
  description: `Alert ${alertId}`,
  timestamp: new Date().toISOString(),
  severity: 'medium',
  acknowledged: false,
});

const AlertsWorkspacePage = ({ role }: { role: string }) => {
  const [alerts, setAlerts] = React.useState<Alert[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [listError, setListError] = React.useState('');
  const [selectedAlert, setSelectedAlert] = React.useState<Alert | null>(null);
  const [details, setDetails] = React.useState<AlertDetails | null>(null);
  const [detailsLoading, setDetailsLoading] = React.useState(false);
  const [detailsError, setDetailsError] = React.useState('');
  const [actionBusy, setActionBusy] = React.useState(false);
  const [severity, setSeverity] = React.useState<AlertSeverityFilter>('All');
  const [search, setSearch] = React.useState('');
  const [ownerInput, setOwnerInput] = React.useState<string>(() => String(getAuthUser()?.id || '').trim());
  const { showNotification } = useNotification();
  const setActivePage = useAppStore((state) => state.setActivePage);
  const globalSeverityFilter = useAppStore((state) => state.globalSeverityFilter);
  const setGlobalSeverityFilter = useAppStore((state) => state.setGlobalSeverityFilter);

  const privileged = role === 'analyst' || role === 'admin';

  React.useEffect(() => {
    const next = severityFromGlobal(globalSeverityFilter);
    setSeverity((prev) => (prev === next ? prev : next));
  }, [globalSeverityFilter]);

  const loadAlerts = React.useCallback(async () => {
    if (!privileged) return;
    setLoading(true);
    setListError('');
    try {
      const res = await getAlertsPaged({ page: 1, page_size: 20, severity, search: search || undefined });
      const nextAlerts = res.data.alerts || [];
      setAlerts(nextAlerts);
      if (!selectedAlert && nextAlerts.length > 0) {
        setSelectedAlert(nextAlerts[0]);
      }
    } catch (error) {
      console.error(error);
      showNotification('Unable to load alerts.', 'error');
      setListError('Unable to load alerts for the current filter.');
    } finally {
      setLoading(false);
    }
  }, [privileged, severity, search, selectedAlert, showNotification]);

  React.useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  React.useEffect(() => {
    const onFocusAlert = (event: Event) => {
      const custom = event as CustomEvent<{ alertId?: string }>;
      const alertId = String(custom.detail?.alertId || '').trim();
      if (!alertId) return;

      const existing = alerts.find((row) => row.backend_id === alertId) || makeSyntheticAlert(alertId);
      setSelectedAlert(existing);
    };
    window.addEventListener('alerts:focus', onFocusAlert as EventListener);
    return () => window.removeEventListener('alerts:focus', onFocusAlert as EventListener);
  }, [alerts]);

  const loadSelectedAlertDetails = React.useCallback(async () => {
    if (!selectedAlert?.backend_id) {
      setDetails(null);
      return;
    }
    setDetailsLoading(true);
    setDetailsError('');
    try {
      const res = await getAlertDetails(selectedAlert.backend_id);
      setDetails(res.data);
    } catch (error) {
      console.error(error);
      showNotification('Unable to load alert evidence.', 'error');
      setDetailsError('Unable to load alert evidence.');
    } finally {
      setDetailsLoading(false);
    }
  }, [selectedAlert?.backend_id, showNotification]);

  React.useEffect(() => {
    void loadSelectedAlertDetails();
  }, [loadSelectedAlertDetails]);

  const openInvestigation = React.useCallback(() => {
    const alertId = String(selectedAlert?.backend_id || '').trim();
    if (!alertId) return;
    try {
      window.dispatchEvent(new CustomEvent('investigation:focus', { detail: { alertId } }));
    } catch {
      // no-op
    }
    setActivePage('investigation');
  }, [selectedAlert?.backend_id, setActivePage]);

  const createCaseForAlert = React.useCallback(async () => {
    const alertId = String(selectedAlert?.backend_id || '').trim();
    if (!alertId || actionBusy) return;
    const existingCaseId = String(details?.linked_case_ids?.[0] || '').trim();
    if (existingCaseId) {
      showNotification(`Alert is already linked to case ${existingCaseId}.`, 'info');
      try {
        window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId: existingCaseId } }));
      } catch {
        // no-op
      }
      return;
    }
    setActionBusy(true);
    try {
      const created = await createCaseFromAlert(alertId);
      const caseId = String(created.data?.id || '').trim();
      showNotification(caseId ? `Case ${caseId} created from alert.` : 'Case created from alert.', 'success');
      if (caseId) {
        try {
          window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId } }));
        } catch {
          // no-op
        }
      }
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to create case from alert.'), 'error');
    } finally {
      setActionBusy(false);
    }
  }, [actionBusy, details?.linked_case_ids, selectedAlert?.backend_id, showNotification]);

  const assignAlertCase = React.useCallback(async () => {
    const alertId = String(selectedAlert?.backend_id || '').trim();
    if (!alertId || actionBusy) return;

    const suggestedOwner = ownerInput || String(getAuthUser()?.id || '').trim();
    const rawOwner = window.prompt('Assign case owner user id for this alert.', suggestedOwner);
    if (rawOwner === null) return;
    const ownerId = rawOwner.trim();
    setOwnerInput(ownerId);

    setActionBusy(true);
    try {
      let caseId = String(details?.linked_case_ids?.[0] || '').trim();
      if (!caseId) {
        const created = await createCaseFromAlert(alertId);
        caseId = String(created.data?.id || '').trim();
      }
      if (caseId && ownerId) {
        await assignCaseOwner(caseId, {
          owner_user_id: ownerId,
          note: 'Assigned directly from Alerts workspace.',
        });
      }
      showNotification(caseId ? `Case ${caseId} assigned${ownerId ? ` to ${ownerId}` : ''}.` : 'Case created and assignment attempted.', 'success');
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to assign case owner from alert.'), 'error');
    } finally {
      setActionBusy(false);
    }
  }, [actionBusy, details?.linked_case_ids, ownerInput, selectedAlert?.backend_id, showNotification]);

  if (!privileged) {
    return <EmptyState title="Alerts workspace restricted" description="Viewer users do not have access to alert triage or evidence inspection." />;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
      <Surface
        title="Alert queue"
        description="Filter by urgency, inspect status, and select an item to investigate."
        actions={
          <>
            <select
              value={severity}
              onChange={(e) => {
                const nextValue = e.target.value as AlertSeverityFilter;
                setSeverity(nextValue);
                const normalized =
                  nextValue === 'All' ? 'all' :
                  nextValue === 'Critical' ? 'critical' :
                  nextValue === 'High' ? 'high' :
                  nextValue === 'Medium' ? 'medium' : 'low';
                setGlobalSeverityFilter(normalized);
              }}
              aria-label="Severity filter"
              className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none"
            >
              {['All', 'Critical', 'High', 'Medium', 'Low'].map((option) => <option key={option}>{option}</option>)}
            </select>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alerts"
              aria-label="Search alerts"
              className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
            />
            <ActionButton onClick={() => void loadAlerts()} variant="primary">
              Refresh
            </ActionButton>
          </>
        }
      >
        {listError ? (
          <div className="mb-4">
            <ErrorState message={listError} onRetry={() => void loadAlerts()} />
          </div>
        ) : null}
        {loading ? (
          <LoadingState label="Retrieving triage items from the backend..." />
        ) : (
          <div className="overflow-hidden rounded-2xl border border-border-dark/70">
            <table className="min-w-full divide-y divide-border-dark/70 text-sm">
              <thead className="bg-dark-tertiary/90 text-text-secondary">
                <tr>
                  <th className="px-4 py-3 text-left font-medium">Alert</th>
                  <th className="px-4 py-3 text-left font-medium">Severity / Risk</th>
                  <th className="px-4 py-3 text-left font-medium">Status</th>
                  <th className="px-4 py-3 text-left font-medium">Owner</th>
                  <th className="px-4 py-3 text-left font-medium">Observed</th>
                  <th className="px-4 py-3 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60 bg-[#0d1729]/60">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-text-secondary">
                      No alerts matched your current filter.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => {
                    const selected = selectedAlert?.backend_id === alert.backend_id;
                    return (
                      <tr
                        key={alert.backend_id || alert.id}
                        onClick={() => setSelectedAlert(alert)}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            setSelectedAlert(alert);
                          }
                        }}
                        tabIndex={0}
                        className={`cursor-pointer transition ${selected ? 'bg-cyan-500/10' : 'hover:bg-dark-tertiary/70'}`}
                        aria-label={`Select alert ${alert.description}`}
                      >
                        <td className="px-4 py-3 text-white">{alert.description}</td>
                        <td className="px-4 py-3"><StatusPill label={alert.severity.toUpperCase()} tone={alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'info'} /></td>
                        <td className="px-4 py-3 text-text-secondary">
                          <StatusPill label={alert.acknowledged ? 'Acknowledged' : 'New'} tone={alert.acknowledged ? 'success' : 'warning'} />
                        </td>
                        <td className="px-4 py-3 text-text-secondary">{userDisplayName(alert.owner, alert.owner_user_id, 'Unassigned')}</td>
                        <td className="px-4 py-3 text-text-secondary">{formatTimestamp(alert.timestamp)}</td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-2">
                            <ActionButton
                              variant="ghost"
                              className="px-2 py-1 text-xs"
                              onClick={() => {
                                setSelectedAlert(alert);
                                const alertId = String(alert.backend_id || '').trim();
                                if (alertId) {
                                  try {
                                    window.dispatchEvent(new CustomEvent('investigation:focus', { detail: { alertId } }));
                                  } catch {
                                    // no-op
                                  }
                                }
                                setActivePage('investigation');
                              }}
                            >
                              Investigate
                            </ActionButton>
                            <ActionButton
                              variant="ghost"
                              className="px-2 py-1 text-xs"
                              onClick={async () => {
                                if (!alert.backend_id) return;
                                try {
                                  await acknowledgeAlert(alert.backend_id, !alert.acknowledged);
                                  showNotification(alert.acknowledged ? 'Alert reopened for review.' : 'Alert acknowledged.', 'success');
                                  await loadAlerts();
                                } catch (error: any) {
                                  showNotification(String(error?.response?.data?.detail || 'Failed to update alert status.'), 'error');
                                }
                              }}
                            >
                              {alert.acknowledged ? 'Reopen' : 'Acknowledge'}
                            </ActionButton>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </Surface>

      <Surface title="Evidence & actions" description="Explanation, context, and immediate next steps for the selected alert.">
        {detailsLoading ? (
          <LoadingState label="Fetching explainability and audit-safe context for the selected alert..." />
        ) : detailsError ? (
          <ErrorState message={detailsError} onRetry={() => void loadSelectedAlertDetails()} />
        ) : details ? (
          <div className="space-y-4">
            <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <StatusPill label={details.severity} tone={String(details.severity).toLowerCase().includes('high') ? 'danger' : 'warning'} />
                <StatusPill label={details.acknowledged ? 'Acknowledged' : 'Needs triage'} tone={details.acknowledged ? 'success' : 'warning'} />
              </div>
              <h3 className="mt-3 text-lg font-semibold text-white">{details.title}</h3>
              <p className="mt-2 text-sm text-text-primary">{details.message}</p>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Source</p>
                <p className="mt-2 text-sm text-white">{details.source_ip || 'Not provided'}</p>
              </div>
              <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Target</p>
                <p className="mt-2 text-sm text-white">{details.target || 'Not provided'}</p>
              </div>
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Ownership</p>
              <p className="mt-2 text-sm text-white">{userDisplayName(details.owner, details.owner_user_id, 'Unassigned')}</p>
              {details.linked_case_owners?.length ? (
                <p className="mt-1 text-xs text-text-secondary">
                  Linked case owners: {details.linked_case_owners.map((owner) => userDisplayName(owner, owner.id, 'Unknown')).join(', ')}
                </p>
              ) : null}
            </div>

            {details.linked_case_ids?.length ? (
              <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Linked cases</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {details.linked_case_ids.map((caseId) => (
                    <button
                      key={caseId}
                      type="button"
                      onClick={() => {
                        try {
                          window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId } }));
                        } catch {
                          // no-op
                        }
                        setActivePage('cases');
                      }}
                      className="rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white hover:border-cyan-400/40"
                    >
                      {caseId}
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            {details.query ? (
              <div className="rounded-2xl border border-border-dark/70 bg-[#09111f] p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Observed query</p>
                <code className="mt-3 block whitespace-pre-wrap break-words text-sm text-cyan-200">{details.query}</code>
              </div>
            ) : null}

            {details.explainability ? (
              <ExplainabilityPanel explanation={details.explainability} title="Alert risk and decision evidence" />
            ) : null}

            {details.explainability?.decision_trace?.length ? (
              <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Decision trace</p>
                <div className="mt-3 space-y-3">
                  {details.explainability.decision_trace.map((step, index) => (
                    <div key={`${step.stage}-${index}`} className="rounded-xl border border-border-dark/60 bg-[#09111f] p-3">
                      <p className="text-sm font-medium text-white">{step.stage}</p>
                      <p className="mt-1 text-sm text-text-secondary">{step.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="flex flex-wrap gap-2">
              <ActionButton
                onClick={async () => {
                  if (!selectedAlert?.backend_id) return;
                  if (!selectedAlert.acknowledged) {
                    const confirmed = window.confirm('Acknowledge this alert as triaged?');
                    if (!confirmed) return;
                  }
                  try {
                    await acknowledgeAlert(selectedAlert.backend_id, !selectedAlert.acknowledged);
                    showNotification(selectedAlert.acknowledged ? 'Alert reopened for review.' : 'Alert acknowledged.', 'success');
                    await loadAlerts();
                  } catch (error: any) {
                    showNotification(String(error?.response?.data?.detail || 'Failed to change alert acknowledgement.'), 'error');
                  }
                }}
                disabled={actionBusy}
                variant="secondary"
              >
                {selectedAlert?.acknowledged ? 'Remove acknowledgement' : 'Acknowledge'}
              </ActionButton>
              <ActionButton
                onClick={() => void createCaseForAlert()}
                disabled={actionBusy}
                variant="primary"
              >
                Create case
              </ActionButton>
              <ActionButton
                onClick={() => void assignAlertCase()}
                disabled={actionBusy}
                variant="secondary"
              >
                {actionBusy ? 'Working...' : 'Assign'}
              </ActionButton>
              <ActionButton
                onClick={openInvestigation}
                disabled={actionBusy}
                variant="ghost"
              >
                Investigate
              </ActionButton>
            </div>
          </div>
        ) : (
          <EmptyState title="Select an alert" description="Choose an alert from the queue to inspect evidence and take action." />
        )}
      </Surface>
    </div>
  );
};

export default AlertsWorkspacePage;
