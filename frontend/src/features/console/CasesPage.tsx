import * as React from 'react';
import { addCaseNote, assignCaseOwner, getCaseDetail, getCases, linkAlertToCase, updateCaseStatus } from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import { ActionButton, Surface, StatusPill, EmptyState, ErrorState, LoadingState } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import { userDisplayMeta, userDisplayName } from '../../lib/userDisplay';
import type { CaseSeverity, CaseStatus, SecurityCaseDetail, SecurityCaseSummary } from '../../types/api';

const PAGE_SIZE = 20;
const STATUS_OPTIONS: Array<'all' | CaseStatus> = ['all', 'new', 'triaged', 'investigating', 'contained', 'closed'];
const SEVERITY_OPTIONS: Array<'all' | CaseSeverity> = ['all', 'Critical', 'High', 'Medium', 'Low'];

const severityTone = (value: CaseSeverity): 'danger' | 'warning' | 'info' =>
  value === 'Critical' || value === 'High' ? 'danger' : value === 'Medium' ? 'warning' : 'info';

const statusTone = (value: CaseStatus): 'success' | 'warning' | 'info' =>
  value === 'closed' ? 'success' : value === 'contained' ? 'info' : 'warning';

const CasesPage = ({ role }: { role: string }) => {
  const privileged = role === 'analyst' || role === 'admin';
  const { showNotification } = useNotification();
  const focusedCaseIdRef = React.useRef<string | null>(null);

  const [rows, setRows] = React.useState<SecurityCaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = React.useState<string | null>(null);
  const [selectedCase, setSelectedCase] = React.useState<SecurityCaseDetail | null>(null);
  const [loadingList, setLoadingList] = React.useState(false);
  const [loadingDetail, setLoadingDetail] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [listError, setListError] = React.useState('');
  const [detailError, setDetailError] = React.useState('');

  const [page, setPage] = React.useState(1);
  const [totalPages, setTotalPages] = React.useState(1);
  const [statusFilter, setStatusFilter] = React.useState<'all' | CaseStatus>('all');
  const [severityFilter, setSeverityFilter] = React.useState<'all' | CaseSeverity>('all');
  const [search, setSearch] = React.useState('');

  const [nextStatus, setNextStatus] = React.useState<CaseStatus>('triaged');
  const [ownerInput, setOwnerInput] = React.useState('');
  const [noteText, setNoteText] = React.useState('');
  const [alertLinkInput, setAlertLinkInput] = React.useState('');
  const [alertLinkNote, setAlertLinkNote] = React.useState('');

  const loadList = React.useCallback(async () => {
    if (!privileged) return;
    setLoadingList(true);
    setListError('');
    try {
      const res = await getCases({
        page,
        page_size: PAGE_SIZE,
        status: statusFilter,
        severity: severityFilter,
        search_term: search.trim() || undefined,
      });
      const list = res.data.cases || [];
      setRows(list);
      setTotalPages(Math.max(1, Number(res.data.total_pages || 1)));
      setSelectedCaseId((prev) => {
        const focusedId = focusedCaseIdRef.current;
        if (focusedId) {
          return focusedId;
        }
        if (prev && list.some((item) => item.id === prev)) return prev;
        return list.length ? list[0].id : null;
      });
    } catch {
      showNotification('Failed to load cases.', 'error');
      setListError('Failed to load case queue data.');
      setRows([]);
      setSelectedCaseId(null);
      setTotalPages(1);
    } finally {
      setLoadingList(false);
    }
  }, [privileged, page, statusFilter, severityFilter, search, showNotification]);

  const loadDetail = React.useCallback(async (caseId: string) => {
    setLoadingDetail(true);
    setDetailError('');
    try {
      const res = await getCaseDetail(caseId);
      const detail = res.data;
      setSelectedCase(detail);
      setOwnerInput(String(detail.owner_user_id || ''));
      setNextStatus(detail.status);
    } catch {
      showNotification('Failed to load case detail.', 'error');
      setDetailError('Failed to load selected case detail.');
      setSelectedCase(null);
    } finally {
      setLoadingDetail(false);
    }
  }, [showNotification]);

  React.useEffect(() => {
    void loadList();
  }, [loadList]);

  React.useEffect(() => {
    const onFocusCase = (event: Event) => {
      const custom = event as CustomEvent<{ caseId?: string }>;
      const caseId = String(custom.detail?.caseId || '').trim();
      if (!caseId) return;
      focusedCaseIdRef.current = caseId;
      setStatusFilter('all');
      setSeverityFilter('all');
      setSearch('');
      setPage(1);
      setSelectedCaseId(caseId);
      void loadDetail(caseId);
    };
    window.addEventListener('cases:focus', onFocusCase as EventListener);
    return () => window.removeEventListener('cases:focus', onFocusCase as EventListener);
  }, [loadDetail]);

  React.useEffect(() => {
    if (!selectedCaseId) {
      setSelectedCase(null);
      return;
    }
    void loadDetail(selectedCaseId);
    if (focusedCaseIdRef.current && focusedCaseIdRef.current === selectedCaseId) {
      focusedCaseIdRef.current = null;
    }
  }, [selectedCaseId, loadDetail]);

  const refreshCurrentCase = React.useCallback(async () => {
    if (!selectedCaseId) return;
    await Promise.all([loadList(), loadDetail(selectedCaseId)]);
  }, [selectedCaseId, loadDetail, loadList]);

  const handleLinkAlert = async () => {
    if (!selectedCase) return;
    const alertId = alertLinkInput.trim();
    if (!alertId) {
      showNotification('Alert ID is required to link.', 'warning');
      return;
    }
    setSaving(true);
    try {
      await linkAlertToCase(selectedCase.id, {
        alert_id: alertId,
        note: alertLinkNote.trim() || undefined,
      });
      setAlertLinkInput('');
      setAlertLinkNote('');
      showNotification(`Linked alert ${alertId} to case.`, 'success');
      await refreshCurrentCase();
    } catch (error: any) {
      showNotification(String(error?.response?.data?.detail || 'Failed to link alert to case.'), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleStatusUpdate = async () => {
    if (!selectedCase) return;
    if (nextStatus === 'closed' && selectedCase.status !== 'closed') {
      const confirmed = window.confirm('Close this case now? You can reopen it later if needed.');
      if (!confirmed) return;
    }
    setSaving(true);
    try {
      await updateCaseStatus(selectedCase.id, {
        status: nextStatus,
        note: noteText.trim() || undefined,
      });
      if (noteText.trim()) setNoteText('');
      showNotification('Case status updated.', 'success');
      await refreshCurrentCase();
    } catch {
      showNotification('Failed to update case status.', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleAssignOwner = async () => {
    if (!selectedCase) return;
    setSaving(true);
    try {
      await assignCaseOwner(selectedCase.id, { owner_user_id: ownerInput.trim() || undefined });
      showNotification('Case owner updated.', 'success');
      await refreshCurrentCase();
    } catch {
      showNotification('Failed to assign case owner.', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleAddNote = async () => {
    if (!selectedCase || !noteText.trim()) return;
    setSaving(true);
    try {
      await addCaseNote(selectedCase.id, { note: noteText.trim() });
      setNoteText('');
      showNotification('Case note added.', 'success');
      await refreshCurrentCase();
    } catch {
      showNotification('Failed to add case note.', 'error');
    } finally {
      setSaving(false);
    }
  };

  if (!privileged) {
    return <EmptyState title="Cases are restricted" description="Case management is limited to analyst and admin roles." />;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_0.95fr]">
      <Surface
        title="Case queue"
        description="Filter and select investigation cases from backend case management."
        actions={
          <>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as 'all' | CaseStatus);
                setPage(1);
              }}
              className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none"
            >
              {STATUS_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value as 'all' | CaseSeverity);
                setPage(1);
              }}
              className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none"
            >
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search title"
              className="rounded-xl border border-border-dark/70 bg-dark-tertiary px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
            />
          </>
        }
      >
        {listError ? (
          <div className="mb-4">
            <ErrorState message={listError} onRetry={() => void loadList()} />
          </div>
        ) : null}
        {loadingList ? (
          <LoadingState label="Retrieving case queue from backend..." />
        ) : rows.length === 0 ? (
          <EmptyState title="No cases found" description="Create cases from Alerts or Investigation, then return here to triage and assign." />
        ) : (
          <div className="space-y-3">
            <div className="overflow-hidden rounded-2xl border border-border-dark/70">
              <table className="min-w-full divide-y divide-border-dark/70 text-sm">
                <thead className="bg-dark-tertiary/90 text-text-secondary">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium">Case</th>
                    <th className="px-4 py-3 text-left font-medium">Severity</th>
                    <th className="px-4 py-3 text-left font-medium">Status</th>
                    <th className="px-4 py-3 text-left font-medium">Owner</th>
                    <th className="px-4 py-3 text-left font-medium">Updated</th>
                    <th className="px-4 py-3 text-left font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-dark/60 bg-[#0d1729]/60">
                  {rows.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => setSelectedCaseId(item.id)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedCaseId(item.id);
                        }
                      }}
                      tabIndex={0}
                      className={`cursor-pointer transition ${selectedCaseId === item.id ? 'bg-cyan-500/10' : 'hover:bg-dark-tertiary/70'}`}
                      aria-label={`Select case ${item.title}`}
                    >
                      <td className="px-4 py-3 text-white">
                        <p className="font-medium">{item.title}</p>
                        <p className="text-xs text-text-secondary">{item.id}</p>
                      </td>
                      <td className="px-4 py-3"><StatusPill label={item.severity} tone={severityTone(item.severity)} /></td>
                      <td className="px-4 py-3"><StatusPill label={item.status} tone={statusTone(item.status)} /></td>
                      <td className="px-4 py-3 text-text-secondary">{userDisplayName(item.owner, item.owner_user_id, 'Unassigned')}</td>
                      <td className="px-4 py-3 text-text-secondary">{formatTimestamp(item.updated_at)}</td>
                      <td className="px-4 py-3">
                        <ActionButton
                          variant="ghost"
                          className="px-2 py-1 text-xs"
                          onClick={() => setSelectedCaseId(item.id)}
                        >
                          Open
                        </ActionButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-border-dark/70 pt-2 text-xs text-text-secondary">
              <span>Page {page} of {totalPages}</span>
              <div className="flex items-center gap-2">
                <ActionButton
                  disabled={page <= 1}
                  onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                  variant="ghost"
                  className="px-2 py-1 text-xs"
                >
                  Prev
                </ActionButton>
                <ActionButton
                  disabled={page >= totalPages}
                  onClick={() => setPage((prev) => prev + 1)}
                  variant="ghost"
                  className="px-2 py-1 text-xs"
                >
                  Next
                </ActionButton>
              </div>
            </div>
          </div>
        )}
      </Surface>

      <Surface title="Case detail" description="Status, ownership, timeline, and analyst notes for the selected case.">
        {loadingDetail ? (
          <LoadingState label="Fetching selected case detail and timeline..." />
        ) : detailError ? (
          <ErrorState message={detailError} onRetry={() => selectedCaseId && void loadDetail(selectedCaseId)} />
        ) : selectedCase ? (
          <div className="space-y-4">
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-semibold text-white">{selectedCase.title}</p>
                  <p className="mt-1 text-sm text-text-secondary">Created {formatTimestamp(selectedCase.created_at)}</p>
                  <p className="mt-1 text-sm text-text-secondary">
                    Owner: {userDisplayName(selectedCase.owner, selectedCase.owner_user_id, 'Unassigned')} - Created by {userDisplayName(selectedCase.created_by, selectedCase.created_by_user_id, 'Unknown')}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <StatusPill
                    label={selectedCase.severity}
                    tone={selectedCase.severity === 'Critical' || selectedCase.severity === 'High' ? 'danger' : selectedCase.severity === 'Medium' ? 'warning' : 'info'}
                  />
                  <StatusPill label={selectedCase.status} tone={selectedCase.status === 'closed' ? 'success' : selectedCase.status === 'contained' ? 'info' : 'warning'} />
                </div>
              </div>
              {selectedCase.description ? <p className="mt-3 text-sm text-text-primary whitespace-pre-wrap">{selectedCase.description}</p> : null}
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <select
                value={nextStatus}
                onChange={(e) => setNextStatus(e.target.value as CaseStatus)}
                className="rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
              >
                {STATUS_OPTIONS.filter((x) => x !== 'all').map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
              <div className="flex gap-2">
                <input
                  value={ownerInput}
                  onChange={(e) => setOwnerInput(e.target.value)}
                  placeholder="Owner user id (UUID)"
                  className="w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
                />
                <ActionButton
                  onClick={handleAssignOwner}
                  disabled={saving}
                  variant="secondary"
                >
                  Assign
                </ActionButton>
              </div>
            </div>

            <textarea
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              rows={3}
              placeholder="Add note or status update reason"
              className="w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
            />
            <div className="flex flex-wrap gap-2">
              <ActionButton
                onClick={handleStatusUpdate}
                disabled={saving}
                variant="primary"
              >
                Update status
              </ActionButton>
              <ActionButton
                onClick={handleAddNote}
                disabled={saving || !noteText.trim()}
                variant="secondary"
              >
                Add note
              </ActionButton>
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Timeline</p>
              <div className="mt-3 space-y-3 max-h-[320px] overflow-y-auto">
                {(selectedCase.activity || selectedCase.timeline || []).length === 0 ? (
                  <p className="text-sm text-text-secondary">No timeline events yet.</p>
                ) : (
                  (selectedCase.activity || selectedCase.timeline || []).map((entry, index) => (
                    <div key={`${entry.timestamp}-${index}`} className="rounded-xl border border-border-dark/60 bg-[#09111f] p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-medium text-white">{entry.action}</p>
                        <p className="text-xs text-text-secondary">{formatTimestamp(entry.timestamp)}</p>
                      </div>
                      {entry.note ? <p className="mt-2 text-sm text-text-primary">{entry.note}</p> : null}
                      {(entry.actor || entry.actor_user_id) ? (
                        <p className="mt-1 text-xs text-text-secondary">
                          Actor: {userDisplayName(entry.actor, entry.actor_user_id, 'System')}
                          {userDisplayMeta(entry.actor, entry.actor_user_id) ? ` (${userDisplayMeta(entry.actor, entry.actor_user_id)})` : ''}
                        </p>
                      ) : null}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4 space-y-3">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Alert links</p>
              <div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]">
                <input
                  value={alertLinkInput}
                  onChange={(e) => setAlertLinkInput(e.target.value)}
                  placeholder="Alert ID (e.g., alert-...)"
                  className="rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
                />
                <input
                  value={alertLinkNote}
                  onChange={(e) => setAlertLinkNote(e.target.value)}
                  placeholder="Optional link note"
                  className="rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none placeholder:text-text-secondary"
                />
                <ActionButton
                  onClick={handleLinkAlert}
                  disabled={saving || !alertLinkInput.trim()}
                  variant="secondary"
                >
                  Link alert
                </ActionButton>
              </div>
              {(selectedCase.alert_links || []).length === 0 ? (
                <p className="text-sm text-text-secondary">No alert links yet.</p>
              ) : (
                <div className="max-h-[180px] space-y-2 overflow-y-auto">
                  {(selectedCase.alert_links || []).map((link) => (
                    <button
                      key={link.id}
                      type="button"
                      onClick={() => {
                        try {
                          window.dispatchEvent(new CustomEvent('alerts:focus', { detail: { alertId: link.alert_id } }));
                        } catch {
                          // no-op
                        }
                      }}
                      className="w-full rounded-xl border border-border-dark/60 bg-[#09111f] px-3 py-2 text-left hover:border-cyan-400/40"
                    >
                      <p className="text-sm text-white">{link.alert_id}</p>
                      <p className="mt-1 text-xs text-text-secondary">
                        Linked {formatTimestamp(link.linked_at)} by {userDisplayName(link.linked_by, link.linked_by_user_id, 'Unknown')}
                      </p>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Case notes</p>
              {(selectedCase.notes || []).length === 0 ? (
                <p className="mt-3 text-sm text-text-secondary">No persisted notes yet.</p>
              ) : (
                <div className="mt-3 max-h-[220px] space-y-2 overflow-y-auto">
                  {(selectedCase.notes || []).map((entry) => (
                    <div key={entry.id} className="rounded-xl border border-border-dark/60 bg-[#09111f] p-3">
                      <p className="text-sm text-white whitespace-pre-wrap">{entry.note}</p>
                      <p className="mt-1 text-xs text-text-secondary">
                        {userDisplayName(entry.author, entry.author_user_id, 'Unknown')} at {formatTimestamp(entry.created_at)}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <EmptyState title="No case selected" description="Choose a case from the queue to review timeline and actions." />
        )}
      </Surface>
    </div>
  );
};

export default CasesPage;
