import * as React from 'react';
import {
  createStepUpToken,
  getGovernanceOverview,
  getStepUpTokenForAction,
  patchSqlEnforcementConfig,
  reloadSpamFraudPatterns,
  reloadSpamReputationAssets,
  updateSpamReputationAssets,
  updateSpamSettings,
  uploadSpamBlocklist,
} from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import { ActionButton, EmptyState, ErrorState, LoadingState, StatTile, StatusPill, Surface } from '../../components/common/ConsoleSurface';
import { formatTimestamp } from '../../lib/dateUtils';
import type { GovernanceDomainSection, GovernanceOverviewResponse } from '../../types/api';

const parseLines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

const supportTone = (support: string): 'success' | 'warning' | 'info' => {
  if (support === 'editable') return 'success';
  if (support === 'partially_supported') return 'warning';
  return 'info';
};

const supportLabel = (support: string): string => {
  if (support === 'editable') return 'Editable';
  if (support === 'partially_supported') return 'Partially supported';
  return 'Read-only';
};

const clamp01 = (value: number): number => Math.max(0, Math.min(1, value));

const readDomain = (overview: GovernanceOverviewResponse | null, key: string): GovernanceDomainSection => {
  const fallback: GovernanceDomainSection = {
    support: 'read_only',
    writable_actions: [],
    controls: {},
    metadata: {},
    notes: [],
  };
  return overview?.domains?.[key] || fallback;
};

const PolicyRulesPage = ({ role }: { role: string }) => {
  const isAdmin = role === 'admin';
  const { showNotification } = useNotification();

  const [overview, setOverview] = React.useState<GovernanceOverviewResponse | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [savingSql, setSavingSql] = React.useState(false);
  const [savingEmail, setSavingEmail] = React.useState(false);
  const [reloadingReputation, setReloadingReputation] = React.useState(false);
  const [updatingReputation, setUpdatingReputation] = React.useState(false);
  const [reloadingFraudPack, setReloadingFraudPack] = React.useState(false);
  const [uploadingBlocklist, setUploadingBlocklist] = React.useState(false);
  const [errorText, setErrorText] = React.useState('');
  const [changedPaths, setChangedPaths] = React.useState<string[]>([]);
  const [selectedBlocklistFile, setSelectedBlocklistFile] = React.useState<File | null>(null);

  const [ddlPolicy, setDdlPolicy] = React.useState('deny_non_migration');
  const [allowlistMode, setAllowlistMode] = React.useState<'safe' | 'regex'>('safe');
  const [monitorBackoff, setMonitorBackoff] = React.useState<number>(3);
  const [requireParameterization, setRequireParameterization] = React.useState(true);
  const [requireServiceContext, setRequireServiceContext] = React.useState(true);
  const [criticalPatternsText, setCriticalPatternsText] = React.useState('');

  const [emailThreshold, setEmailThreshold] = React.useState<number>(0.5);
  const [emailSuspiciousTldsText, setEmailSuspiciousTldsText] = React.useState('');

  const hydrateSqlForm = React.useCallback((rules: Record<string, any>) => {
    setDdlPolicy(String(rules?.ddl_exec?.policy || 'deny_non_migration'));
    setAllowlistMode(rules?.allowlist?.mode === 'regex' ? 'regex' : 'safe');
    setMonitorBackoff(Number(rules?.monitor?.backoff_n || 3));
    setRequireParameterization(Boolean(rules?.parameterization?.require));
    setRequireServiceContext(Boolean(rules?.service_context?.require));
    setCriticalPatternsText((Array.isArray(rules?.critical_patterns) ? rules.critical_patterns : []).join('\n'));
  }, []);

  const hydrateEmailForm = React.useCallback((section: GovernanceDomainSection) => {
    const runtime = (section.controls?.runtime_settings || {}) as Record<string, any>;
    const policyDefaults = (section.controls?.policy_defaults || {}) as Record<string, any>;
    const thresholdValue = runtime?.thresholds?.suspicious ?? runtime?.final_threshold ?? policyDefaults?.final_threshold ?? 0.5;
    setEmailThreshold(clamp01(Number.isFinite(Number(thresholdValue)) ? Number(thresholdValue) : 0.5));
    const tlds = runtime?.suspicious_tlds ?? policyDefaults?.suspicious_tlds ?? [];
    setEmailSuspiciousTldsText(Array.isArray(tlds) ? tlds.map((item) => String(item)).join('\n') : '');
  }, []);

  const loadOverview = React.useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setErrorText('');
    try {
      const res = await getGovernanceOverview();
      const payload = res.data as GovernanceOverviewResponse;
      setOverview(payload);
      hydrateSqlForm((payload.domains?.sql?.controls || {}) as Record<string, any>);
      hydrateEmailForm(readDomain(payload, 'email'));
      setChangedPaths([]);
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to load governance overview.'));
    } finally {
      setLoading(false);
    }
  }, [hydrateEmailForm, hydrateSqlForm, isAdmin]);

  React.useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  const confirmAction = React.useCallback((message: string): boolean => {
    return window.confirm(message);
  }, []);

  const getStepUpToken = React.useCallback(
    async (action: string): Promise<string | null> => {
      let stepUpToken = getStepUpTokenForAction(action);
      if (stepUpToken) return stepUpToken;
      const password = window.prompt('Step-up authentication required. Enter your current password.');
      if (!password) {
        showNotification('Step-up cancelled.', 'warning');
        return null;
      }
      await createStepUpToken(password, [action]);
      stepUpToken = getStepUpTokenForAction(action);
      if (!stepUpToken) {
        showNotification('Step-up token unavailable for this action.', 'error');
        return null;
      }
      return stepUpToken;
    },
    [showNotification]
  );

  const handleSaveSql = React.useCallback(async () => {
    if (!overview) return;
    if (!confirmAction('Apply SQL governance changes? A service restart may be required.')) return;
    setSavingSql(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('config.sql_enforcement.patch');
      if (!stepUpToken) return;
      const payload = {
        critical_patterns: parseLines(criticalPatternsText),
        ddl_exec: { policy: ddlPolicy as 'deny_non_migration' | 'deny' | 'monitor' | 'allow' },
        allowlist: { mode: allowlistMode },
        monitor: { backoff_n: Number.isFinite(monitorBackoff) && monitorBackoff > 0 ? monitorBackoff : 3 },
        parameterization: { require: requireParameterization },
        service_context: { require: requireServiceContext },
      };
      const res = await patchSqlEnforcementConfig(payload, stepUpToken);
      setChangedPaths(res.data.changed_paths || []);
      await loadOverview();
      showNotification('SQL governance updated. Restart is required to apply changes.', 'success');
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to update SQL governance.'));
      showNotification('Failed to update SQL governance.', 'error');
    } finally {
      setSavingSql(false);
    }
  }, [
    allowlistMode,
    confirmAction,
    criticalPatternsText,
    ddlPolicy,
    getStepUpToken,
    loadOverview,
    monitorBackoff,
    overview,
    requireParameterization,
    requireServiceContext,
    showNotification,
  ]);

  const handleSaveEmailSettings = React.useCallback(async () => {
    if (!overview) return;
    if (!confirmAction('Apply email governance settings now?')) return;
    setSavingEmail(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('spam.settings.update');
      if (!stepUpToken) return;
      await updateSpamSettings(
        {
          final_threshold: clamp01(emailThreshold),
          suspicious_tlds: parseLines(emailSuspiciousTldsText),
        },
        stepUpToken
      );
      await loadOverview();
      showNotification('Email governance settings updated.', 'success');
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to update email settings.'));
      showNotification('Failed to update email settings.', 'error');
    } finally {
      setSavingEmail(false);
    }
  }, [confirmAction, emailSuspiciousTldsText, emailThreshold, getStepUpToken, loadOverview, overview, showNotification]);

  const handleReloadReputation = React.useCallback(async () => {
    if (!confirmAction('Reload local reputation assets now?')) return;
    setReloadingReputation(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('spam.settings.update');
      if (!stepUpToken) return;
      await reloadSpamReputationAssets(stepUpToken);
      await loadOverview();
      showNotification('Email reputation assets reloaded.', 'success');
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to reload reputation assets.'));
      showNotification('Failed to reload reputation assets.', 'error');
    } finally {
      setReloadingReputation(false);
    }
  }, [confirmAction, getStepUpToken, loadOverview, showNotification]);

  const handleUpdateReputation = React.useCallback(async () => {
    if (!confirmAction('Fetch and apply upstream reputation updates now?')) return;
    setUpdatingReputation(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('spam.settings.update');
      if (!stepUpToken) return;
      await updateSpamReputationAssets(stepUpToken);
      await loadOverview();
      showNotification('Upstream reputation ingest completed.', 'success');
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to update reputation feeds.'));
      showNotification('Failed to update reputation feeds.', 'error');
    } finally {
      setUpdatingReputation(false);
    }
  }, [confirmAction, getStepUpToken, loadOverview, showNotification]);

  const handleReloadFraudPatterns = React.useCallback(async () => {
    if (!confirmAction('Reload fraud pattern pack now?')) return;
    setReloadingFraudPack(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('spam.settings.update');
      if (!stepUpToken) return;
      await reloadSpamFraudPatterns(stepUpToken);
      await loadOverview();
      showNotification('Fraud pattern pack reloaded.', 'success');
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to reload fraud pattern pack.'));
      showNotification('Failed to reload fraud pattern pack.', 'error');
    } finally {
      setReloadingFraudPack(false);
    }
  }, [confirmAction, getStepUpToken, loadOverview, showNotification]);

  const handleUploadBlocklist = React.useCallback(async () => {
    if (!selectedBlocklistFile) {
      showNotification('Select a blocklist file first.', 'warning');
      return;
    }
    if (!confirmAction(`Upload and apply blocklist file "${selectedBlocklistFile.name}"?`)) return;
    setUploadingBlocklist(true);
    setErrorText('');
    try {
      const stepUpToken = await getStepUpToken('spam.blocklist.upload');
      if (!stepUpToken) return;
      await uploadSpamBlocklist(selectedBlocklistFile, stepUpToken);
      await loadOverview();
      showNotification('Domain blocklist uploaded and reloaded.', 'success');
      setSelectedBlocklistFile(null);
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to upload domain blocklist.'));
      showNotification('Failed to upload domain blocklist.', 'error');
    } finally {
      setUploadingBlocklist(false);
    }
  }, [confirmAction, getStepUpToken, loadOverview, selectedBlocklistFile, showNotification]);

  if (!isAdmin) {
    return <EmptyState title="Policy & rules restricted" description="Only admin users can inspect or change governance controls." />;
  }

  if (loading && !overview) {
    return <LoadingState label="Loading unified governance overview..." />;
  }

  const sqlSection = readDomain(overview, 'sql');
  const fileSection = readDomain(overview, 'file');
  const emailSection = readDomain(overview, 'email');
  const suppressionSection = readDomain(overview, 'suppressions');

  const sqlRestartRequired = Boolean(sqlSection.metadata?.restart_required);
  const emailRuntime = (emailSection.controls?.runtime_settings || {}) as Record<string, any>;
  const fileControls = fileSection.controls || {};
  const suppressions = suppressionSection.controls || {};
  const sqlAllowlistMode = String((suppressions?.sql_allowlist || {}).mode || '-');
  const sqlAllowlistPatternCount = Array.isArray(suppressions?.sql_ddl_allowlist_patterns)
    ? suppressions.sql_ddl_allowlist_patterns.length
    : 0;
  const emailAllowlistCount = Number(suppressions?.email_allowlist?.count || 0);
  const emailBlocklistCount = Number(suppressions?.email_blocklist?.count || 0);

  return (
    <div className="space-y-6">
      {errorText ? <ErrorState message={errorText} onRetry={() => void loadOverview()} /> : null}

      <Surface
        title="Unified governance overview"
        description="One admin surface for active controls, support boundaries, and recent governance changes."
        actions={
          <ActionButton
            onClick={() => void loadOverview()}
            disabled={loading}
            variant="secondary"
          >
            {loading ? 'Loading...' : 'Reload'}
          </ActionButton>
        }
      >
        <div className="grid gap-4 md:grid-cols-4">
          {[
            { key: 'sql', title: 'SQL controls', section: sqlSection },
            { key: 'file', title: 'File controls', section: fileSection },
            { key: 'email', title: 'Email controls', section: emailSection },
            { key: 'suppressions', title: 'Suppressions', section: suppressionSection },
          ].map((item) => (
            <div key={item.key} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">{item.title}</p>
              <div className="mt-3">
                <StatusPill label={supportLabel(item.section.support)} tone={supportTone(item.section.support)} />
              </div>
              <p className="mt-3 text-xs text-text-secondary">Writable actions: {item.section.writable_actions.length}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-text-secondary">
          <span>Tenant scope: {overview?.tenant_id || '-'}</span>
          <span>As of: {overview?.as_of ? formatTimestamp(overview.as_of) : '-'}</span>
        </div>
      </Surface>

      <Surface
        title="SQL governance controls"
        description="Editable SQL enforcement controls backed by prevention_rules.yml and step-up protected patch APIs."
        actions={
          <ActionButton
            onClick={() => void handleSaveSql()}
            disabled={savingSql || loading}
            variant="primary"
          >
            {savingSql ? 'Saving...' : 'Save SQL controls'}
          </ActionButton>
        }
      >
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <StatusPill label={supportLabel(sqlSection.support)} tone={supportTone(sqlSection.support)} />
          <StatusPill label={sqlRestartRequired ? 'Restart required' : 'Hot reload'} tone={sqlRestartRequired ? 'warning' : 'success'} />
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">DDL Exec Policy</p>
            <select
              value={ddlPolicy}
              onChange={(e) => setDdlPolicy(e.target.value)}
              className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
            >
              <option value="deny_non_migration">deny_non_migration</option>
              <option value="deny">deny</option>
              <option value="monitor">monitor</option>
              <option value="allow">allow</option>
            </select>
          </div>

          <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Allowlist mode</p>
            <select
              value={allowlistMode}
              onChange={(e) => setAllowlistMode(e.target.value === 'regex' ? 'regex' : 'safe')}
              className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
            >
              <option value="safe">safe</option>
              <option value="regex">regex</option>
            </select>
          </div>

          <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Monitor backoff (N)</p>
            <input
              type="number"
              min={1}
              value={monitorBackoff}
              onChange={(e) => setMonitorBackoff(Number(e.target.value || 1))}
              className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
            />
          </div>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4 text-sm text-white">
            <input
              type="checkbox"
              checked={requireParameterization}
              onChange={(e) => setRequireParameterization(e.target.checked)}
              className="mr-2 align-middle"
            />
            Require parameterization
          </label>
          <label className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4 text-sm text-white">
            <input
              type="checkbox"
              checked={requireServiceContext}
              onChange={(e) => setRequireServiceContext(e.target.checked)}
              className="mr-2 align-middle"
            />
            Require service context
          </label>
        </div>

        <div className="mt-4 rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Critical patterns (one per line)</p>
          <textarea
            value={criticalPatternsText}
            onChange={(e) => setCriticalPatternsText(e.target.value)}
            rows={8}
            className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
          />
        </div>

        {changedPaths.length > 0 ? <div className="mt-4 text-xs text-text-secondary">Updated paths: {changedPaths.join(', ')}</div> : null}
      </Surface>

      <Surface
        title="Email governance controls"
        description="Partially supported controls: settings and reputation assets are writable; other email governance values are runtime-only."
        actions={
          <ActionButton
            onClick={() => void handleSaveEmailSettings()}
            disabled={savingEmail || loading}
            variant="primary"
          >
            {savingEmail ? 'Saving...' : 'Save email settings'}
          </ActionButton>
        }
      >
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <StatusPill label={supportLabel(emailSection.support)} tone={supportTone(emailSection.support)} />
          <StatusPill label={emailRuntime?.transformer_enabled ? 'Transformer enabled' : 'Transformer unavailable'} tone={emailRuntime?.transformer_enabled ? 'success' : 'warning'} />
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <StatTile label="Reputation entries" value={emailRuntime?.reputation_entries ?? '-'} tone="info" />
          <StatTile label="Allowlist count" value={emailRuntime?.allowlist_count ?? '-'} tone="success" />
          <StatTile label="Blocklist count" value={emailRuntime?.blocklist_count ?? '-'} tone="warning" />
          <StatTile label="Fraud patterns" value={emailRuntime?.fraud_pattern_count ?? '-'} tone="info" />
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Suspicious threshold</p>
            <input
              type="number"
              min={0}
              max={1}
              step={0.01}
              value={emailThreshold}
              onChange={(e) => setEmailThreshold(clamp01(Number(e.target.value || 0)))}
              className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
            />
          </div>

          <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Domain blocklist upload</p>
            <input
              type="file"
              accept=".txt"
              onChange={(event) => setSelectedBlocklistFile(event.target.files?.[0] || null)}
              className="mt-3 block w-full text-sm text-text-secondary file:mr-3 file:rounded-xl file:border-0 file:bg-cyan-500/10 file:px-3 file:py-2 file:text-cyan-200"
            />
            <ActionButton
              onClick={() => void handleUploadBlocklist()}
              disabled={uploadingBlocklist || !selectedBlocklistFile}
              variant="secondary"
              className="mt-3"
            >
              {uploadingBlocklist ? 'Uploading...' : 'Upload blocklist'}
            </ActionButton>
          </div>
        </div>

        <div className="mt-4 rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Suspicious TLDs (one per line)</p>
          <textarea
            value={emailSuspiciousTldsText}
            onChange={(e) => setEmailSuspiciousTldsText(e.target.value)}
            rows={6}
            className="mt-3 w-full rounded-xl border border-border-dark/70 bg-[#09111f] px-3 py-2 text-sm text-white outline-none"
          />
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <ActionButton
            onClick={() => void handleReloadReputation()}
            disabled={reloadingReputation}
            variant="secondary"
          >
            {reloadingReputation ? 'Reloading...' : 'Reload reputation assets'}
          </ActionButton>
          <ActionButton
            onClick={() => void handleUpdateReputation()}
            disabled={updatingReputation}
            variant="secondary"
          >
            {updatingReputation ? 'Updating...' : 'Update reputation from upstream'}
          </ActionButton>
          <ActionButton
            onClick={() => void handleReloadFraudPatterns()}
            disabled={reloadingFraudPack}
            variant="secondary"
          >
            {reloadingFraudPack ? 'Reloading...' : 'Reload fraud patterns'}
          </ActionButton>
        </div>
      </Surface>

      <Surface
        title="File governance controls"
        description="Current file controls are available for visibility and audit, but write operations remain read-only in this release."
      >
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <StatusPill label={supportLabel(fileSection.support)} tone={supportTone(fileSection.support)} />
          <StatusPill label={fileSection.metadata?.runtime_ready ? 'Runtime ready' : 'Runtime not ready'} tone={fileSection.metadata?.runtime_ready ? 'success' : 'warning'} />
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <StatTile label="YARA files" value={fileSection.metadata?.rule_file_count ?? '-'} tone="info" />
          <StatTile label="PoC policy" value={String(fileControls?.poc_policy || '-')} tone="warning" />
          <StatTile label="Archive depth" value={fileControls?.archive_limits?.max_depth ?? '-'} tone="neutral" />
          <StatTile
            label="Last YARA update"
            value={fileSection.metadata?.latest_modified_at ? formatTimestamp(fileSection.metadata.latest_modified_at) : '-'}
            tone="info"
          />
        </div>

        <pre className="mt-4 max-h-[280px] overflow-auto rounded-2xl border border-border-dark/70 bg-[#09111f] p-4 text-xs text-cyan-200">
          {JSON.stringify(fileControls, null, 2)}
        </pre>
      </Surface>

      <Surface
        title="Suppressions and exceptions"
        description="Current suppression visibility is partial. SQL allowlist and email allow/block lists are visible, but dedicated exception lifecycle APIs are not implemented yet."
      >
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <StatusPill label={supportLabel(suppressionSection.support)} tone={supportTone(suppressionSection.support)} />
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <StatTile label="SQL allowlist mode" value={sqlAllowlistMode} tone="info" />
          <StatTile label="SQL allowlist patterns" value={sqlAllowlistPatternCount} tone="info" />
          <StatTile label="Email allow/block entries" value={`${emailAllowlistCount}/${emailBlocklistCount}`} tone="warning" />
        </div>
        <div className="mt-4 text-xs text-text-secondary">File allow-domains map: {JSON.stringify(suppressions?.file_allow_domains || {})}</div>
      </Surface>

      <Surface title="Recent governance changes" description="Tenant-scoped control-plane history sourced from audit logs.">
        {(overview?.recent_changes || []).length === 0 ? (
          <EmptyState title="No governance changes yet" description="No matching governance actions were found in recent audit history." />
        ) : (
          <div className="space-y-3">
            {(overview?.recent_changes || []).map((entry) => (
              <div key={entry.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-medium text-white">{entry.action}</p>
                  <StatusPill label={entry.success ? 'success' : 'failed'} tone={entry.success ? 'success' : 'danger'} />
                </div>
                <p className="mt-1 text-xs text-text-secondary">
                  {formatTimestamp(entry.timestamp)} - {entry.actor?.display_name || entry.actor_user_id || 'system'} - {entry.resource_type || 'resource'}:{' '}
                  {entry.resource_id || '-'}
                </p>
              </div>
            ))}
          </div>
        )}
      </Surface>
    </div>
  );
};

export default PolicyRulesPage;
