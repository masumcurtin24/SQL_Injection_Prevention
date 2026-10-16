// File: frontend/src/store/appStore.ts

import { create } from 'zustand';
import type { DashboardStats, LiveEvent } from '../types/api';

export type Page =
  | 'dashboard'
  | 'alerts'
  | 'cases'
  | 'investigation'
  | 'sqlSecurity'
  | 'fileSecurity'
  | 'emailSecurity'
  | 'platformHealth'
  | 'auditLog'
  | 'modelOps'
  | 'policyRules'
  | 'userManagement';
export type GlobalTimeRange = '24h' | '7d' | '30d' | 'total';
export type LiveFeedScopeType = 'admin' | 'viewer';
export type GlobalSeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

export interface LiveFeedMeta {
  scope?: LiveFeedScopeType;
  day?: string | null;
  before?: string | null;
  event_types?: string;
  next_before?: string | null;
  has_more?: boolean;
  limit?: number;
}

const TENANT_SELECTION_KEY = 'active_tenant_id';

export interface TenantOption {
  id: string;
  slug: string;
  name: string;
  is_active: boolean;
}

const loadSelectedTenant = (): string => {
  try {
    return String(localStorage.getItem(TENANT_SELECTION_KEY) || '').trim();
  } catch {
    return '';
  }
};

interface AppState {
  stats: DashboardStats;
  liveEvents: LiveEvent[];
  liveFeedMeta: LiveFeedMeta | null;
  setStats: (stats: DashboardStats) => void;
  setLiveEvents: (events: LiveEvent[]) => void;
  setLiveFeedMeta: (meta: LiveFeedMeta | null) => void;
  mergeLiveEvents: (events: LiveEvent[]) => void;
  incrementQueries: () => void;
  incrementMaliciousQueries: () => void;
  incrementFilesScanned: () => void;
  incrementSpamDetected: () => void;
  addLiveEvent: (event: LiveEvent) => void;
  activePage: Page;
  setActivePage: (page: Page) => void;
  globalTimeRange: GlobalTimeRange;
  setGlobalTimeRange: (value: GlobalTimeRange) => void;
  globalSeverityFilter: GlobalSeverityFilter;
  setGlobalSeverityFilter: (value: GlobalSeverityFilter) => void;
  selectedTenant: string;
  setSelectedTenant: (value: string) => void;
  tenantOptions: TenantOption[];
  setTenantOptions: (options: TenantOption[]) => void;
  hasNewAlert: boolean;
  setHasNewAlert: (v: boolean) => void;
}

const MAX_LIVE_EVENTS = 1000;

const normalizeLiveEvents = (events: LiveEvent[]): LiveEvent[] => {
  const map = new Map<string, LiveEvent>();
  for (const event of events) {
    const id = String(event?.id || '');
    const type = String(event?.type || '');
    if (!id || !type) continue;
    const key = `${type}:${id}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, event);
      continue;
    }
    const existingTs = String(existing.timestamp || '');
    const candidateTs = String(event.timestamp || '');
    if (candidateTs > existingTs) {
      map.set(key, event);
    }
  }
  return Array.from(map.values())
    .sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
    .slice(0, MAX_LIVE_EVENTS);
};

export const useAppStore = create<AppState>((set) => ({
  stats: {
    total_queries: 0,
    malicious_queries: 0,
    files_scanned: 0,
    spam_detected: 0,
    sql_risk_posture_score: 0,
    sql_precision_score: 0,
    sql_avg_calibrated_risk: 0,
    sql_high_risk_rate: 0,
    sql_precision_sample_size: 0,
  },
  liveEvents: [],
  liveFeedMeta: null,
  setStats: (stats) => set({ stats }),
  setLiveEvents: (events) => set({ liveEvents: normalizeLiveEvents(events) }),
  setLiveFeedMeta: (meta) => set({ liveFeedMeta: meta }),
  mergeLiveEvents: (events) =>
    set((state) => ({ liveEvents: normalizeLiveEvents([...state.liveEvents, ...events]) })),
  incrementQueries: () =>
    set((state) => ({
      stats: { ...state.stats, total_queries: state.stats.total_queries + 1 },
    })),
  incrementMaliciousQueries: () =>
    set((state) => ({
      stats: { ...state.stats, malicious_queries: state.stats.malicious_queries + 1 },
    })),
  incrementFilesScanned: () =>
    set((state) => ({
      stats: { ...state.stats, files_scanned: state.stats.files_scanned + 1 },
    })),
  incrementSpamDetected: () =>
    set((state) => ({
      stats: { ...state.stats, spam_detected: state.stats.spam_detected + 1 },
    })),
  addLiveEvent: (event) =>
    set((state) => ({ liveEvents: normalizeLiveEvents([event, ...state.liveEvents]) })),
  activePage: 'dashboard',
  setActivePage: (page) => set({ activePage: page }),
  globalTimeRange: '24h',
  setGlobalTimeRange: (value) => set({ globalTimeRange: value }),
  globalSeverityFilter: 'all',
  setGlobalSeverityFilter: (value) => set({ globalSeverityFilter: value }),
  selectedTenant: loadSelectedTenant(),
  setSelectedTenant: (value) => {
    const normalized = String(value || '').trim();
    set({ selectedTenant: normalized });
    try {
      if (normalized) localStorage.setItem(TENANT_SELECTION_KEY, normalized);
      else localStorage.removeItem(TENANT_SELECTION_KEY);
    } finally {
      window.dispatchEvent(new Event('tenant:changed'));
    }
  },
  tenantOptions: [],
  setTenantOptions: (options) => set({ tenantOptions: options }),
  hasNewAlert: false,
  setHasNewAlert: (v) => set({ hasNewAlert: v }),
}));
