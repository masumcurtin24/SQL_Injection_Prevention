import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Bell,
  Bot,
  ClipboardList,
  FileText,
  HeartPulse,
  LayoutDashboard,
  LogOut,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Workflow,
  ScrollText,
  Users,
  Wrench,
} from 'lucide-react';
import {
  createStepUpToken,
  getAlertsPaged,
  getAuthUser,
  getCases,
  getTenants,
  getStepUpTokenForAction,
  runSpamAutopipelineNow,
} from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import { useWebSocket } from '../../contexts/useWebSocket';
import { ActionButton, StatusPill } from '../common/ConsoleSurface';
import { useAppStore, type GlobalSeverityFilter, type GlobalTimeRange, type Page } from '../../store/appStore';
import type { Alert, SecurityCaseSummary } from '../../types/api';
import {
  ALLOWED_PAGES_BY_ROLE,
  NAV_PAGE_ORDER,
  PAGE_META,
  normalizeRole,
} from '../../features/console/consoleConfig';

interface AppShellProps {
  children: ReactNode;
  role: string;
  onLogout: () => void;
}

type NavItem = {
  page: Page;
  label: string;
  icon: ReactNode;
};

type QuickAction = {
  id: string;
  label: string;
  visible: boolean;
  run: () => Promise<void> | void;
};

const NAV_ICONS: Record<Page, ReactNode> = {
  dashboard: <LayoutDashboard className="h-4 w-4" />,
  alerts: <Bell className="h-4 w-4" />,
  cases: <ClipboardList className="h-4 w-4" />,
  investigation: <Workflow className="h-4 w-4" />,
  sqlSecurity: <Shield className="h-4 w-4" />,
  fileSecurity: <FileText className="h-4 w-4" />,
  emailSecurity: <ShieldCheck className="h-4 w-4" />,
  platformHealth: <HeartPulse className="h-4 w-4" />,
  auditLog: <ScrollText className="h-4 w-4" />,
  modelOps: <Bot className="h-4 w-4" />,
  policyRules: <SlidersHorizontal className="h-4 w-4" />,
  userManagement: <Users className="h-4 w-4" />,
};

const TIME_RANGE_LABELS: Record<GlobalTimeRange, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
  total: 'Lifetime',
};

const SEVERITY_FILTER_LABELS: Record<GlobalSeverityFilter, string> = {
  all: 'All severities',
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const AppShell = ({ children, role, onLogout }: AppShellProps) => {
  const {
    activePage,
    setActivePage,
    hasNewAlert,
    setHasNewAlert,
    globalTimeRange,
    setGlobalTimeRange,
    globalSeverityFilter,
    setGlobalSeverityFilter,
    selectedTenant,
    setSelectedTenant,
    tenantOptions,
    setTenantOptions,
  } = useAppStore();
  const ws = useWebSocket();
  const { showNotification } = useNotification();
  const user = getAuthUser();
  const currentRole = normalizeRole(role);
  const userFullName = String(user?.full_name || '').trim();
  const userDisplay = userFullName || user?.email || 'Unknown';
  const visibleItems = NAV_PAGE_ORDER
    .filter((page) => ALLOWED_PAGES_BY_ROLE[currentRole].includes(page))
    .map((page): NavItem => ({ page, label: PAGE_META[page].label, icon: NAV_ICONS[page] }));
  const canSearchAlerts = currentRole === 'admin' || currentRole === 'analyst';
  const canSearchCases = currentRole === 'admin' || currentRole === 'analyst';
  const pageMeta = PAGE_META[activePage];

  const [searchQuery, setSearchQuery] = useState('');
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchAlerts, setSearchAlerts] = useState<Alert[]>([]);
  const [searchCases, setSearchCases] = useState<SecurityCaseSummary[]>([]);
  const [searchOpen, setSearchOpen] = useState(false);

  const [quickOpen, setQuickOpen] = useState(false);
  const [quickBusy, setQuickBusy] = useState(false);
  const [tenantLoading, setTenantLoading] = useState(false);
  const quickRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const closeMenus = (event: MouseEvent) => {
      const target = event.target as Node | null;
      if (quickRef.current && target && !quickRef.current.contains(target)) {
        setQuickOpen(false);
      }
      if (searchRef.current && target && !searchRef.current.contains(target)) {
        setSearchOpen(false);
      }
    };
    window.addEventListener('mousedown', closeMenus);
    return () => window.removeEventListener('mousedown', closeMenus);
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const isCommandK = (event.ctrlKey || event.metaKey) && String(event.key || '').toLowerCase() === 'k';
      if (!isCommandK) return;
      event.preventDefault();
      setSearchOpen(true);
      searchInputRef.current?.focus();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    const query = searchQuery.trim();
    if (query.length < 2) {
      setSearchAlerts([]);
      setSearchCases([]);
      setSearchLoading(false);
      return;
    }
    let cancelled = false;
    setSearchLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const alertReq = canSearchAlerts
          ? getAlertsPaged({ page: 1, page_size: 5, severity: 'All', search: query })
          : Promise.resolve<{ data: { alerts: Alert[] } }>({ data: { alerts: [] } });
        const caseReq = canSearchCases
          ? getCases({ page: 1, page_size: 5, search_term: query, status: 'all', severity: 'all' })
          : Promise.resolve<{ data: { cases: SecurityCaseSummary[] } }>({ data: { cases: [] } });
        const [alertsRes, casesRes] = await Promise.all([alertReq, caseReq]);
        if (cancelled) return;
        setSearchAlerts((alertsRes.data as any).alerts || []);
        setSearchCases((casesRes.data as any)?.cases || []);
      } catch {
        if (cancelled) return;
        setSearchAlerts([]);
        setSearchCases([]);
      } finally {
        if (!cancelled) setSearchLoading(false);
      }
    }, 280);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [canSearchAlerts, canSearchCases, searchQuery]);

  const searchHasResults = searchAlerts.length > 0 || searchCases.length > 0;

  useEffect(() => {
    let cancelled = false;
    const loadTenants = async () => {
      setTenantLoading(true);
      try {
        const res = await getTenants();
        if (cancelled) return;
        const options = Array.isArray(res.data?.tenants)
          ? res.data.tenants.map((row) => ({
              id: String(row.id || ''),
              slug: String(row.slug || ''),
              name: String(row.name || row.slug || row.id),
              is_active: Boolean(row.is_active),
            }))
          : [];
        setTenantOptions(options);

        const currentTenantId = String(res.data?.current_tenant_id || '').trim();
        const selected = String(selectedTenant || '').trim();
        const selectedValid = Boolean(selected && options.some((row) => row.id === selected));
        if (!selectedValid) {
          const fallback = currentTenantId || options[0]?.id || '';
          if (fallback && fallback !== selected) {
            setSelectedTenant(fallback);
          }
        }
      } catch {
        if (cancelled) return;
        setTenantOptions([]);
      } finally {
        if (!cancelled) setTenantLoading(false);
      }
    };
    void loadTenants();
    return () => {
      cancelled = true;
    };
  }, [selectedTenant, setSelectedTenant, setTenantOptions]);

  const focusAlertFromSearch = (alertId: string) => {
    if (!alertId) return;
    setActivePage('alerts');
    setSearchOpen(false);
    try {
      window.dispatchEvent(new CustomEvent('alerts:focus', { detail: { alertId } }));
    } catch {
      // no-op
    }
  };

  const focusCaseFromSearch = (caseId: string) => {
    setActivePage('cases');
    setSearchOpen(false);
    try {
      window.dispatchEvent(new CustomEvent('cases:focus', { detail: { caseId } }));
    } catch {
      // no-op
    }
  };

  const runSpamAutopipeline = useCallback(async () => {
    const action = 'defender.spam.autopipeline.run';
    let token = getStepUpTokenForAction(action);
    if (!token) {
      const password = window.prompt('Step-up required. Enter your current password to run the spam autopipeline.');
      if (!password) {
        showNotification('Step-up cancelled.', 'warning');
        return;
      }
      await createStepUpToken(password, [action]);
      token = getStepUpTokenForAction(action);
      if (!token) {
        showNotification('Step-up token not available for this action.', 'error');
        return;
      }
    }
    await runSpamAutopipelineNow(token);
    showNotification('Spam autopipeline run started.', 'success');
  }, [showNotification]);

  const quickActions = useMemo<QuickAction[]>(
    () => [
      {
        id: 'open-alerts',
        label: 'Open Alerts Workspace',
        visible: currentRole === 'admin' || currentRole === 'analyst',
        run: () => setActivePage('alerts'),
      },
      {
        id: 'open-investigation',
        label: 'Open Investigation',
        visible: currentRole === 'admin' || currentRole === 'analyst',
        run: () => setActivePage('investigation'),
      },
      {
        id: 'open-sql',
        label: 'Open SQL Security',
        visible: currentRole === 'admin' || currentRole === 'analyst' || currentRole === 'viewer',
        run: () => setActivePage('sqlSecurity'),
      },
      {
        id: 'open-file',
        label: 'Open File Security',
        visible: currentRole === 'admin' || currentRole === 'analyst' || currentRole === 'viewer',
        run: () => setActivePage('fileSecurity'),
      },
      {
        id: 'open-email',
        label: 'Open Email Security',
        visible: currentRole === 'admin' || currentRole === 'analyst' || currentRole === 'viewer',
        run: () => setActivePage('emailSecurity'),
      },
      {
        id: 'open-model-ops',
        label: 'Open Model Ops',
        visible: currentRole === 'admin' || currentRole === 'analyst' || currentRole === 'reviewer',
        run: () => setActivePage('modelOps'),
      },
      {
        id: 'open-platform-health',
        label: 'Open Platform Health',
        visible: currentRole === 'admin' || currentRole === 'analyst' || currentRole === 'reviewer',
        run: () => setActivePage('platformHealth'),
      },
      {
        id: 'run-spam-autopipeline',
        label: 'Run Spam Autopipeline Now',
        visible: currentRole === 'admin',
        run: runSpamAutopipeline,
      },
    ],
    [currentRole, runSpamAutopipeline, setActivePage]
  );
  const visibleQuickActions = quickActions.filter((a) => a.visible);

  const runQuickAction = async (action: QuickAction) => {
    setQuickBusy(true);
    try {
      await action.run();
      setQuickOpen(false);
    } catch (error: any) {
      const detail = String(error?.response?.data?.detail || 'Quick action failed.');
      showNotification(detail, 'error');
    } finally {
      setQuickBusy(false);
    }
  };
  const tenantSelectDisabled = tenantLoading || currentRole !== 'admin' || tenantOptions.length <= 1;

  return (
    <div className="min-h-screen bg-[#0a1220] text-text-primary">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="border-r border-border-dark/70 bg-[#0e1727] px-5 py-6">
          <div className="flex items-center gap-3 border-b border-border-dark/70 pb-5">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-400/30">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Middleware Security</p>
              <p className="text-xs text-text-secondary">AI-assisted operations console</p>
            </div>
          </div>

          <nav className="mt-6 space-y-1.5">
            {visibleItems.map((item) => {
              const isActive = item.page === activePage;
              return (
                <button
                  key={item.page}
                  onClick={() => {
                    setActivePage(item.page);
                    if (item.page === 'alerts') setHasNewAlert(false);
                  }}
                  aria-current={isActive ? 'page' : undefined}
                  aria-label={`Open ${item.label}`}
                  className={`flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-sm transition ${
                    isActive
                      ? 'bg-cyan-500/12 text-white ring-1 ring-cyan-400/30'
                      : 'text-text-secondary hover:bg-dark-tertiary/80 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-3">
                    <span className={isActive ? 'text-cyan-300' : 'text-text-secondary'}>{item.icon}</span>
                    <span>{item.label}</span>
                  </span>
                  {item.page === 'alerts' && hasNewAlert ? <span className="h-2.5 w-2.5 rounded-full bg-red-400 shadow-[0_0_12px_rgba(248,113,113,0.9)]" /> : null}
                </button>
              );
            })}
          </nav>

          <div className="mt-8 rounded-2xl border border-border-dark/70 bg-dark-secondary/80 p-4">
            <div className="flex items-center gap-3">
              <div className={`h-2.5 w-2.5 rounded-full ${ws?.status === 'connected' ? 'bg-emerald-400' : ws?.status === 'connecting' ? 'bg-amber-400' : 'bg-red-400'}`} />
              <div>
                <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Realtime</p>
                <p className="text-sm font-medium capitalize text-white">{ws?.status || 'disconnected'}</p>
              </div>
            </div>
            <p className="mt-3 text-xs text-text-secondary">
              Role: <span className="font-medium text-white capitalize">{currentRole}</span>
            </p>
          </div>
        </aside>

        <div className="min-w-0">
          <header className="sticky top-0 z-30 border-b border-border-dark/70 bg-[#0b1424]/95 px-5 py-4 backdrop-blur lg:px-8">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-cyan-300">Security operations</p>
                <h1 className="mt-1 text-2xl font-semibold text-white">{pageMeta.title}</h1>
                <p className="mt-1 text-sm text-text-secondary">{pageMeta.description}</p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div ref={searchRef} className="relative">
                  <label className="flex min-w-[280px] items-center gap-2 rounded-xl border border-border-dark/70 bg-dark-secondary/80 px-3 py-2 text-sm text-text-secondary">
                    <Search className="h-4 w-4" />
                    <input
                      ref={searchInputRef}
                      value={searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                        setSearchOpen(true);
                      }}
                      onFocus={() => setSearchOpen(true)}
                      className="w-full bg-transparent text-white outline-none placeholder:text-text-secondary"
                      placeholder="Search alerts and cases (Ctrl/Cmd+K)"
                      aria-label="Search alerts and cases"
                    />
                    {searchQuery ? (
                      <button
                        type="button"
                        onClick={() => {
                          setSearchQuery('');
                          setSearchOpen(false);
                        }}
                        className="rounded px-1 py-0.5 text-xs text-text-secondary hover:bg-dark-tertiary hover:text-white"
                        aria-label="Clear search"
                      >
                        Clear
                      </button>
                    ) : null}
                  </label>
                  {searchOpen ? (
                    <div className="absolute right-0 mt-2 max-h-[420px] w-[420px] overflow-auto rounded-2xl border border-border-dark/70 bg-[#0d1627] p-3 shadow-2xl">
                      {searchLoading ? (
                        <p className="text-sm text-text-secondary">Searching backend data...</p>
                      ) : searchQuery.trim().length < 2 ? (
                        <p className="text-sm text-text-secondary">Type at least 2 characters.</p>
                      ) : !searchHasResults ? (
                        <p className="text-sm text-text-secondary">No matching alerts or cases.</p>
                      ) : (
                        <div className="space-y-3">
                          {searchAlerts.length > 0 ? (
                            <div>
                              <p className="mb-1 text-xs uppercase tracking-[0.14em] text-cyan-300">Alerts</p>
                              <div className="space-y-1">
                                {searchAlerts.map((alert) => (
                                  <button
                                    key={alert.backend_id || alert.id}
                                    onClick={() => focusAlertFromSearch(String(alert.backend_id || ''))}
                                    className="w-full rounded-lg border border-border-dark/70 bg-dark-tertiary/70 px-3 py-2 text-left text-sm text-white hover:border-cyan-400/40"
                                  >
                                    <p className="truncate">{alert.description}</p>
                                    <p className="mt-1 text-xs text-text-secondary">{alert.severity.toUpperCase()}</p>
                                  </button>
                                ))}
                              </div>
                            </div>
                          ) : null}
                          {searchCases.length > 0 ? (
                            <div>
                              <p className="mb-1 text-xs uppercase tracking-[0.14em] text-cyan-300">Cases</p>
                              <div className="space-y-1">
                                {searchCases.map((row) => (
                                  <button
                                    key={row.id}
                                    onClick={() => focusCaseFromSearch(row.id)}
                                    className="w-full rounded-lg border border-border-dark/70 bg-dark-tertiary/70 px-3 py-2 text-left text-sm text-white hover:border-cyan-400/40"
                                  >
                                    <p className="truncate">{row.title}</p>
                                    <p className="mt-1 text-xs text-text-secondary">{row.status} - {row.severity}</p>
                                  </button>
                                ))}
                              </div>
                            </div>
                          ) : null}
                        </div>
                      )}
                    </div>
                  ) : null}
                </div>

                <label className="rounded-xl border border-border-dark/70 bg-dark-secondary/80 px-3 py-2 text-sm text-text-secondary">
                  <span className="mr-2 text-xs uppercase tracking-[0.14em]">Window</span>
                  <select
                    value={globalTimeRange}
                    onChange={(e) => setGlobalTimeRange(e.target.value as GlobalTimeRange)}
                    aria-label="Global time window"
                    className="bg-transparent text-white outline-none"
                  >
                    <option value="24h">{TIME_RANGE_LABELS['24h']}</option>
                    <option value="7d">{TIME_RANGE_LABELS['7d']}</option>
                    <option value="30d">{TIME_RANGE_LABELS['30d']}</option>
                    <option value="total">{TIME_RANGE_LABELS.total}</option>
                  </select>
                </label>

                <label className="rounded-xl border border-border-dark/70 bg-dark-secondary/80 px-3 py-2 text-sm text-text-secondary">
                  <span className="mr-2 text-xs uppercase tracking-[0.14em]">Severity</span>
                  <select
                    value={globalSeverityFilter}
                    onChange={(e) => setGlobalSeverityFilter(e.target.value as GlobalSeverityFilter)}
                    aria-label="Global severity filter"
                    className="bg-transparent text-white outline-none"
                  >
                    {Object.entries(SEVERITY_FILTER_LABELS).map(([key, label]) => (
                      <option key={key} value={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="rounded-xl border border-border-dark/70 bg-dark-secondary/80 px-3 py-2 text-sm text-text-secondary">
                  <span className="mr-2 text-xs uppercase tracking-[0.14em]">Tenant</span>
                  <select
                    value={selectedTenant}
                    onChange={(e) => setSelectedTenant(e.target.value)}
                    disabled={tenantSelectDisabled}
                    aria-label="Tenant selector"
                    className="bg-transparent text-white outline-none"
                  >
                    {tenantOptions.length > 0 ? (
                      tenantOptions.map((tenant) => (
                        <option key={tenant.id} value={tenant.id}>
                          {tenant.name}
                        </option>
                      ))
                    ) : (
                      <option value={selectedTenant || ''}>
                        {selectedTenant || 'Default'}
                      </option>
                    )}
                  </select>
                </label>

                {visibleQuickActions.length > 0 ? (
                  <div className="relative" ref={quickRef}>
                    <ActionButton
                      onClick={() => setQuickOpen((prev) => !prev)}
                      variant="secondary"
                      className="inline-flex items-center gap-2 bg-dark-secondary/80"
                      ariaLabel="Open quick actions menu"
                    >
                      <Wrench className="h-4 w-4" />
                      Quick Action
                    </ActionButton>
                    {quickOpen ? (
                      <div className="absolute right-0 mt-2 min-w-[260px] rounded-2xl border border-border-dark/70 bg-[#0d1627] p-2 shadow-2xl">
                        {visibleQuickActions.map((action) => (
                          <button
                            key={action.id}
                            onClick={() => void runQuickAction(action)}
                            disabled={quickBusy}
                            className="w-full rounded-lg px-3 py-2 text-left text-sm text-white hover:bg-dark-tertiary disabled:opacity-50"
                            aria-label={action.label}
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ) : null}

                <div className="rounded-xl border border-border-dark/70 bg-dark-secondary/80 px-3 py-2 text-sm text-text-secondary">
                  <span className="mr-2 text-xs uppercase tracking-[0.14em]">User</span>
                  <span className="text-white">{userDisplay}</span>
                </div>
                <StatusPill
                  label={`Realtime ${ws?.status || 'disconnected'}`}
                  tone={ws?.status === 'connected' ? 'success' : ws?.status === 'connecting' ? 'warning' : 'danger'}
                />
                <ActionButton
                  onClick={onLogout}
                  variant="danger"
                  className="inline-flex items-center gap-2"
                  ariaLabel="Sign out"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </ActionButton>
              </div>
            </div>
          </header>

          <main className="px-5 py-6 lg:px-8">{children}</main>
        </div>
      </div>
    </div>
  );
};

export default AppShell;
