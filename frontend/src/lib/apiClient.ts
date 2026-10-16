// File: frontend/src/lib/apiClient.ts

import axios from 'axios';
// Using `import type` is crucial to prevent circular dependency errors at runtime.
import type {
  AnalysisApiResponse,
  SQLQueryPayload,
  SpamAnalysisResponse,
  FileAnalysisResponse,
  Alert,
  AlertDetails,
  DashboardStats,
  DashboardStatsHistoryResponse,
  DashboardFileScanItem,
  DashboardSQLQueryItem,
  DashboardSpamDetectionItem,
  LiveEventDetail,
  DashboardExecutiveOverview,
  DashboardPlatformHealthResponse,
  DashboardAccessFeedResponse,
  CaseActivityResponse,
  CaseAlertLinksResponse,
  CaseNotesResponse,
  SecurityCaseDetail,
  SecurityCaseListResponse,
  SecurityCaseStatsResponse,
  CaseStatus,
  CaseSeverity,
  InvestigationTimelineResponse,
  AuditListResponse,
  DefenderModelInfo,
  DefenderStatusResponse,
  DefenderTrainingJobInfo,
  GovernanceOverviewResponse,
  SqlEnforcementConfigResponse,
  SqlEnforcementPatchPayload,
  SqlEnforcementPatchResponse,
  SpamAutopipelineStatusResponse,
} from '../types/api';

const AUTH_TOKEN_KEY = 'auth_access_token';
const AUTH_USER_KEY = 'auth_user';
const AUTH_STEP_UP_SESSION_KEY = 'auth_step_up_session';
const TENANT_SELECTION_KEY = 'active_tenant_id';
const DEFAULT_API_BASE_URL =
  typeof window !== 'undefined' && !['localhost', '127.0.0.1'].includes(window.location.hostname)
    ? '/api/v1'
    : 'http://localhost:8000/api/v1';
export const API_BASE_URL = ((import.meta as any)?.env?.VITE_API_BASE_URL || DEFAULT_API_BASE_URL).replace(/\/+$/, '');

export interface AuthUser {
  id: string;
  email: string;
  tenant_id: string;
  full_name?: string | null;
  role: string;
}

export interface AdminUser {
  id: string;
  email: string;
  tenant_id: string;
  full_name?: string | null;
  role: 'admin' | 'analyst' | 'reviewer' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface TenantSummary {
  id: string;
  slug: string;
  name: string;
  is_active: boolean;
}

export interface TenantListApiResponse {
  current_tenant_id: string;
  tenants: TenantSummary[];
}

export interface LoginApiResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  refresh_token?: string;
  refresh_expires_in?: number;
  user: AuthUser;
}

export interface StepUpApiResponse {
  step_up_token: string;
  token_type: 'bearer';
  expires_in: number;
  actions: string[];
}

interface StepUpSessionStore {
  token: string;
  expires_at_ms: number;
  actions: string[];
}

export const getAccessToken = (): string | null => {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
};

export const getAuthUser = (): AuthUser | null => {
  try {
    const raw = localStorage.getItem(AUTH_USER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<AuthUser>;
    const tenantId = String(parsed?.tenant_id || '').trim();
    if (!tenantId) return null;
    return {
      id: String(parsed?.id || ''),
      email: String(parsed?.email || ''),
      tenant_id: tenantId,
      full_name: parsed?.full_name ?? null,
      role: String(parsed?.role || ''),
    };
  } catch {
    return null;
  }
};

export const getSelectedTenantId = (): string | null => {
  try {
    const value = String(localStorage.getItem(TENANT_SELECTION_KEY) || '').trim();
    return value || null;
  } catch {
    return null;
  }
};

export const setSelectedTenantId = (tenantId: string): void => {
  const normalized = String(tenantId || '').trim();
  if (!normalized) return;
  try {
    localStorage.setItem(TENANT_SELECTION_KEY, normalized);
  } finally {
    window.dispatchEvent(new Event('tenant:changed'));
  }
};

export const setAuthSession = (token: string, user: AuthUser): void => {
  try {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
    const role = String(user?.role || '').trim().toLowerCase();
    const userTenantId = String(user?.tenant_id || '').trim();
    if (userTenantId) {
      const selectedTenantId = getSelectedTenantId();
      if (!selectedTenantId || role !== 'admin') {
        localStorage.setItem(TENANT_SELECTION_KEY, userTenantId);
      }
    }
  } finally {
    window.dispatchEvent(new Event('auth:changed'));
    window.dispatchEvent(new Event('tenant:changed'));
  }
};

export const clearStepUpSession = (): void => {
  try {
    localStorage.removeItem(AUTH_STEP_UP_SESSION_KEY);
  } finally {
    window.dispatchEvent(new Event('stepup:changed'));
  }
};

export const getStepUpSession = (): StepUpSessionStore | null => {
  try {
    const raw = localStorage.getItem(AUTH_STEP_UP_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StepUpSessionStore>;
    const token = String(parsed?.token || '');
    const expiresAt = Number(parsed?.expires_at_ms || 0);
    const actions = Array.isArray(parsed?.actions) ? parsed.actions.map((v) => String(v)) : [];
    if (!token || expiresAt <= Date.now()) {
      clearStepUpSession();
      return null;
    }
    return { token, expires_at_ms: expiresAt, actions };
  } catch {
    clearStepUpSession();
    return null;
  }
};

export const getStepUpTokenForAction = (action: string): string | null => {
  const session = getStepUpSession();
  if (!session) return null;
  const wanted = String(action || '').trim();
  if (!wanted) return session.token;
  const actions = session.actions || [];
  if (actions.includes('*') || actions.includes(wanted)) return session.token;
  return null;
};

export const setStepUpSession = (payload: StepUpApiResponse): void => {
  const expiresIn = Math.max(Number(payload?.expires_in || 0), 0);
  const token = String(payload?.step_up_token || '').trim();
  if (!token || expiresIn <= 0) {
    clearStepUpSession();
    return;
  }
  const actions = Array.isArray(payload?.actions) ? payload.actions.map((v) => String(v).trim()).filter(Boolean) : ['*'];
  const safeSkewMs = 5_000;
  const store: StepUpSessionStore = {
    token,
    expires_at_ms: Date.now() + expiresIn * 1000 - safeSkewMs,
    actions: actions.length > 0 ? actions : ['*'],
  };
  try {
    localStorage.setItem(AUTH_STEP_UP_SESSION_KEY, JSON.stringify(store));
  } finally {
    window.dispatchEvent(new Event('stepup:changed'));
  }
};

export const clearAuthSession = (): void => {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(AUTH_USER_KEY);
    localStorage.removeItem(AUTH_STEP_UP_SESSION_KEY);
  } finally {
    window.dispatchEvent(new Event('auth:changed'));
    window.dispatchEvent(new Event('stepup:changed'));
  }
};

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  const tenantId = getSelectedTenantId() || getAuthUser()?.tenant_id || '';
  if (token) {
    config.headers = config.headers || {};
    (config.headers as any).Authorization = `Bearer ${token}`;
  }
  if (tenantId) {
    config.headers = config.headers || {};
    (config.headers as any)['X-Tenant-ID'] = tenantId;
  }
  return config;
});

let hasLoggedUnauthorized = false;

apiClient.interceptors.response.use(
  (response) => {
    hasLoggedUnauthorized = false;
    return response;
  },
  (error) => {
    const status = error?.response?.status;
    const requestUrl = String(error?.config?.url || '');
    const isLoginRequest = requestUrl.includes('/auth/login');
    if (status === 401 && !isLoginRequest) {
      const hadToken = Boolean(getAccessToken());
      if (hadToken) {
        clearAuthSession();
      }
      if (!hasLoggedUnauthorized) {
        console.warn('Session is not authenticated. Please sign in again.');
        hasLoggedUnauthorized = true;
      }
      return Promise.reject(error);
    }
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export const login = async (email: string, password: string): Promise<LoginApiResponse> => {
  const response = await apiClient.post('/auth/login', { email, password });
  const payload = response.data as LoginApiResponse;
  setAuthSession(payload.access_token, payload.user);
  return payload;
};

export const getCurrentUser = async (): Promise<{ data: AuthUser }> => {
  const response = await apiClient.get('/auth/me');
  const raw = response.data as any;
  const user: AuthUser = {
    id: String(raw?.id ?? ''),
    email: String(raw?.email ?? ''),
    tenant_id: String(raw?.tenant_id ?? ''),
    full_name:
      raw?.full_name === null || raw?.full_name === undefined
        ? null
        : String(raw.full_name),
    role: String(raw?.role ?? ''),
  };
  if (!user.id || !user.email || !user.role || !user.tenant_id) {
    throw new Error('Invalid /auth/me response payload');
  }
  return { data: user };
};

export const getTenants = async (): Promise<{ data: TenantListApiResponse }> => {
  const response = await apiClient.get('/auth/tenants');
  const raw = response.data as Partial<TenantListApiResponse>;
  const tenants = Array.isArray(raw?.tenants)
    ? raw.tenants.map((row) => ({
        id: String((row as any)?.id || '').trim(),
        slug: String((row as any)?.slug || '').trim(),
        name: String((row as any)?.name || '').trim(),
        is_active: Boolean((row as any)?.is_active),
      })).filter((row) => row.id && row.slug)
    : [];
  const current_tenant_id = String(raw?.current_tenant_id || '').trim();
  return { data: { current_tenant_id, tenants } };
};

export const createStepUpToken = async (
  password: string,
  actions: string[] = []
): Promise<{ data: StepUpApiResponse }> => {
  const response = await apiClient.post('/auth/step-up', { password, actions });
  const payload = response.data as StepUpApiResponse;
  setStepUpSession(payload);
  return { data: payload };
};

export const getUsers = (): Promise<{ data: { users: AdminUser[] } }> => {
  return apiClient.get('/auth/users');
};

export const createUser = (payload: {
  email: string;
  tenant_id?: string;
  full_name?: string | null;
  password: string;
  role: 'admin' | 'analyst' | 'reviewer' | 'viewer';
  is_active?: boolean;
}): Promise<{ data: AdminUser }> => {
  return apiClient.post('/auth/users', payload);
};

export const updateUser = (
  userId: string,
  payload: {
    tenant_id?: string;
    full_name?: string | null;
    role?: 'admin' | 'analyst' | 'reviewer' | 'viewer';
    is_active?: boolean;
    password?: string;
  }
): Promise<{ data: AdminUser }> => {
  return apiClient.patch(`/auth/users/${encodeURIComponent(userId)}`, payload);
};

export const deleteUser = (
  userId: string
): Promise<{ data: { success: boolean; detail: string; user_id: string; email: string } }> => {
  return apiClient.delete(`/auth/users/${encodeURIComponent(userId)}`);
};


export const analyzeQuery = (payload: SQLQueryPayload): Promise<AnalysisApiResponse> => {
  // Backend: app.include_router(analysis_router.router, prefix="/api/v1/analyze-sql")
  return apiClient.post('/analyze-sql/query', payload).then((res) => res.data as AnalysisApiResponse);
};

const parseRawEmailInput = (raw: string): { subject?: string; sender_email?: string; body_text: string } => {
  const text = String(raw ?? '');
  const lines = text.split(/\r?\n/);
  let subject: string | undefined;
  let senderEmail: string | undefined;
  const consumed = new Set<number>();

  for (let i = 0; i < Math.min(lines.length, 16); i += 1) {
    const line = (lines[i] ?? '').trim();
    if (!line) continue;
    if (!subject) {
      const mSub = line.match(/^subject\s*:\s*(.+)$/i);
      if (mSub) {
        subject = mSub[1].trim();
        consumed.add(i);
        continue;
      }
    }
    if (!senderEmail) {
      const mSender = line.match(/^(?:from|sender)\s*:\s*(.+)$/i);
      if (mSender) {
        senderEmail = mSender[1].trim();
        consumed.add(i);
      }
    }
  }

  const bodyText = lines
    .filter((_, idx) => !consumed.has(idx))
    .join('\n')
    .trim();

  return { subject, sender_email: senderEmail, body_text: bodyText || text.trim() };
};

export const analyzeSpam = (text: string): Promise<{ data: SpamAnalysisResponse }> => {
  // Backend: spam analyzer endpoint is POST /api/v1/analyze-spam/email with body { body_text }
  const parsed = parseRawEmailInput(text);
  return apiClient
    .post('/analyze-spam/email', parsed)
    .then((res) => {
      const api = res.data as any; // EmailAnalysisResponse
      const cls = api?.spam_classification || {};
      const decisionConfidence = Number(cls?.decision_confidence ?? api?.decision_confidence ?? api?.explanation?.confidence);
      const mapped: SpamAnalysisResponse = {
        analysis_id: typeof api?.analysis_id === 'string' ? api.analysis_id : undefined,
        is_spam: Boolean(cls?.is_spam ?? false),
        spam_score: Number(cls?.spam_score ?? 0),
        decision_confidence: Number.isFinite(decisionConfidence) ? decisionConfidence : undefined,
        classification_label: typeof cls?.classification_label === 'string' ? cls.classification_label : undefined,
        score_breakdown: api?.score_breakdown || undefined,
        url_indicators: api?.url_indicators || undefined,
        meta_features: api?.meta_features || undefined,
        explanation: api?.explanation || undefined,
        ai_reliability: api?.ai_reliability || api?.explanation?.ai_reliability || undefined,
        decision_display: api?.decision_display || undefined,
        defender_actions: Array.isArray(api?.defender_actions) ? api.defender_actions : undefined,
        defender_action_summary: api?.defender_action_summary || undefined,
      };
      return { data: mapped };
    });
};

// Spam feedback API (online learner)
export const submitSpamFeedback = (
  text: string,
  label: 'Spam'|'Ham',
  options?: {
    subject?: string;
    sender_email?: string;
    predicted_label?: string;
    confidence?: number;
    analysis_id?: string;
    source?: 'human' | 'system';
    notes?: string;
  }
): Promise<{ data: any }> => {
  const parsed = parseRawEmailInput(text);
  const subject = options?.subject ?? parsed.subject;
  const sender_email = options?.sender_email ?? parsed.sender_email;
  const body_text = parsed.body_text || text;
  return apiClient.post('/analyze-spam/feedback', {
    body_text,
    label,
    subject,
    sender_email,
    predicted_label: options?.predicted_label,
    confidence: options?.confidence,
    analysis_id: options?.analysis_id,
    source: options?.source,
    notes: options?.notes,
  });
};

export const getSpamSettings = (): Promise<{ data: any }> => {
  return apiClient.get('/analyze-spam/settings');
};

export const reloadSpamReputationAssets = (stepUpToken?: string): Promise<{ data: any }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.post('/analyze-spam/reputation/reload', undefined, { headers });
};

export const updateSpamReputationAssets = (stepUpToken?: string): Promise<{ data: any }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.post('/analyze-spam/reputation/update', undefined, { headers });
};

export const reloadSpamFraudPatterns = (stepUpToken?: string): Promise<{ data: any }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.post('/analyze-spam/reputation/fraud-patterns/reload', undefined, { headers });
};

export const uploadSpamBlocklist = (file: File, stepUpToken?: string): Promise<{ data: any }> => {
  const form = new FormData();
  form.append('file', file);
  const headers: Record<string, string> = { 'Content-Type': 'multipart/form-data' };
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.post('/analyze-spam/blocklist', form, { headers });
};

export const updateSpamSettings = (
  payload: {
    final_threshold?: number;
    suspicious_tlds?: string[];
    thresholds?: Record<string, number>;
    feature_weights?: Record<string, number>;
    calibration?: Record<string, number>;
    allow_threshold?: number;
    suspicious_threshold?: number;
    block_threshold?: number;
    ood_threshold?: number;
  },
  stepUpToken?: string
): Promise<{ data: any }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.put('/analyze-spam/settings', payload, { headers });
};

export const analyzeFile = (file: File): Promise<{ data: FileAnalysisResponse }> => {
  // Backend: file analyzer endpoint is POST /api/v1/analyze-file/file (UploadFile under 'file')
  const formData = new FormData();
  formData.append('file', file);
  return apiClient
    .post('/analyze-file/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    .then((res) => {
      const api = res.data as any; // Rich backend response
      const status = String(api?.overall_assessment?.overall_status ?? '');
      const action = String(api?.overall_assessment?.recommended_action ?? '');
      const risk = api?.overall_assessment?.risk_score;
      const decisionConfidence = api?.explanation?.decision_confidence ?? api?.explanation?.confidence ?? api?.structured_verdict?.confidence;
      // Treat explicit malicious, suspicious, or any BLOCK/QUARANTINE recommendation as unsafe
      const isMalicious = /malicious/i.test(status) || /suspicious/i.test(status) || /^BLOCK/i.test(action) || /QUARANTINE/i.test(action);
      // Extract matched YARA rules from scan_details if available
      const scanDetails = api?.file_details?.malware_scan?.scan_details || {};
      const outer: string[] = Array.isArray(scanDetails?.outer_yara_matches) ? scanDetails.outer_yara_matches : [];
      const innerArr: any[] = Array.isArray(scanDetails?.inner_yara_matches) ? scanDetails.inner_yara_matches : [];
      const inner: string[] = ([] as string[]).concat(...innerArr.map((m: any) => Array.isArray(m?.rules) ? m.rules : []));
      const matchedSet = new Set<string>([...(outer || []), ...(inner || [])]);
      // Supplement from reasoning when YARA is missing but indicators exist
      const reasons: string[] = Array.isArray(api?.overall_assessment?.reasoning) ? api.overall_assessment.reasoning : [];
      for (const r of reasons) {
        if (typeof r !== 'string') continue;
        const s = r.trim();
        if (s.startsWith('PoC YARA rules:')) {
          const rest = s.substring('PoC YARA rules:'.length).trim();
          rest.split(',').map(t => t.trim()).filter(Boolean).forEach(rule => matchedSet.add(rule));
        } else if (s.startsWith('YARA match inside archive:')) {
          const arrow = s.lastIndexOf('->');
          if (arrow !== -1) {
            const rule = s.substring(arrow + 2).trim();
            if (rule) matchedSet.add(rule);
          }
        } else if (/Exploit write-up indicators/i.test(s)) {
          matchedSet.add('exploit_poc_writeup_generic');
        }
      }
      const matchedRules = Array.from(matchedSet);
      const filename = String(api?.file_details?.filename ?? api?.filename ?? file.name);
      const mime = String(api?.file_details?.type_validation?.detected_mime_type || '') || undefined;
      const fsize = typeof api?.file_details?.filesize_kb === 'number' ? Number(api.file_details.filesize_kb) : null;
      const shortSummary = [
        status ? `Status: ${status}` : null,
        typeof risk === 'number' ? `Risk: ${risk.toFixed(2)}` : null,
        action ? `Recommended: ${action}` : null,
      ].filter(Boolean).join(' • ');

      const mapped: FileAnalysisResponse = {
        analysis_id: typeof api?.analysis_id === 'string' ? api.analysis_id : undefined,
        analysis_timestamp: typeof api?.analysis_timestamp === 'string' ? api.analysis_timestamp : undefined,
        filename,
        is_malicious: isMalicious,
        matched_rules: matchedRules,
        overall_status: status || undefined,
        recommended_action: action || undefined,
        risk_score: typeof risk === 'number' ? risk : null,
        decision_confidence: typeof decisionConfidence === 'number' ? decisionConfidence : null,
        reasoning: reasons,
        mime_type: mime,
        file_size_kb: fsize,
        short_summary: shortSummary || undefined,
        highlights: Array.isArray(api?.highlights) ? api.highlights : undefined,
        file_details: api?.file_details || undefined,
        overall_assessment: api?.overall_assessment || undefined,
        structured_verdict: api?.structured_verdict || undefined,
        macro_defense: api?.macro_defense || api?.file_details?.macro_defense || api?.structured_verdict?.macro_defense || undefined,
        explanation: api?.explanation || undefined,
        ai_reliability: api?.ai_reliability || api?.explanation?.ai_reliability || undefined,
      };
      return { data: mapped };
    });
};

// Helper to map severity from backend to UI shape
const mapSeverity = (sev: string | null | undefined): 'low' | 'medium' | 'high' => {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
};

// Simple string hash to numeric id for UI when backend id is string
const strHash = (s: string): number => {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
};

export const getAlerts = (): Promise<{ data: Alert[] }> => {
  // Backend: returns AlertsListResponse { alerts: [...], total_alerts, ... }
  return apiClient.get('/alerts').then((res) => {
    const list = (res.data?.alerts || []) as any[];
    const mapped: Alert[] = list.map((a) => ({
      id: strHash(String(a.id ?? '')),
      backend_id: String(a.id ?? ''),
      tenant_id: a?.tenant_id ?? null,
      description: a.title ? `${a.title}${a.message ? `: ${a.message}` : ''}` : (a.message || 'Alert'),
      timestamp: a.timestamp,
      severity: mapSeverity(a.severity),
      acknowledged: Boolean(a.acknowledged),
      owner_user_id: a?.owner_user_id ?? null,
      owner: a?.owner ?? null,
    }));
    return { data: mapped };
  });
};

export const getAlertDetails = (id: string): Promise<{ data: AlertDetails }> => {
  return apiClient.get(`/alerts/${encodeURIComponent(id)}`);
};

export const acknowledgeAlert = (id: string, acknowledge: boolean): Promise<{ data: any }> => {
  return apiClient.patch(`/alerts/${encodeURIComponent(id)}/acknowledge`, undefined, { params: { acknowledge } });
};

export interface AlertsQuery {
  page?: number;
  page_size?: number;
  severity?: 'All' | 'Critical' | 'High' | 'Medium' | 'Low';
  acknowledged?: boolean;
  search?: string;
}

export const getAlertsPaged = (q: AlertsQuery): Promise<{ data: { alerts: Alert[]; total_alerts: number; page: number; page_size: number; total_pages: number } }> => {
  const params: any = {
    page: q.page ?? 1,
    page_size: q.page_size ?? 10,
    severity: q.severity && q.severity !== 'All' ? q.severity : undefined,
    acknowledged: q.acknowledged,
    search_term: q.search,
  };
  return apiClient.get('/alerts', { params }).then((res) => {
    const list = (res.data?.alerts || []) as any[];
    const mapped: Alert[] = list.map((a) => ({
      id: strHash(String(a.id ?? '')),
      backend_id: String(a.id ?? ''),
      tenant_id: a?.tenant_id ?? null,
      description: a.title ? `${a.title}${a.message ? `: ${a.message}` : ''}` : (a.message || 'Alert'),
      timestamp: a.timestamp,
      severity: mapSeverity(a.severity),
      acknowledged: Boolean(a.acknowledged),
      owner_user_id: a?.owner_user_id ?? null,
      owner: a?.owner ?? null,
    }));
    return {
      data: {
        alerts: mapped,
        total_alerts: Number(res.data?.total_alerts ?? mapped.length),
        page: Number(res.data?.page ?? params.page),
        page_size: Number(res.data?.page_size ?? params.page_size),
        total_pages: Number(res.data?.total_pages ?? 1),
      },
    };
  });
};

export const getDashboardStats = (scope: 'today' | 'total' = 'today', day?: string): Promise<{ data: DashboardStats }> => {
  // Backend: app.include_router(dashboard_router.router, prefix="/api/v1/dashboard")
  const params: any = { scope };
  if (day) params.day = day;
  return apiClient.get('/dashboard/stats', { params });
};

export const getDashboardExecutiveOverview = (
  scope: 'today' | 'total' = 'today',
  day?: string
): Promise<{ data: DashboardExecutiveOverview }> => {
  const params: any = { scope };
  if (day) params.day = day;
  return apiClient.get('/dashboard/executive-overview', { params });
};

export const getDashboardStatsHistory = (days: number = 30): Promise<{ data: DashboardStatsHistoryResponse }> => {
  return apiClient.get('/dashboard/stats-history', { params: { days } });
};

export const getDashboardPlatformHealth = (
  top: number = 20,
  fpDays: number = 30,
  analystOnly: boolean = true
): Promise<{ data: DashboardPlatformHealthResponse }> => {
  return apiClient.get('/dashboard/platform-health', {
    params: { top, fp_days: fpDays, analyst_only: analystOnly },
  });
};

export const getDashboardAccessFeed = (
  limit: number = 50,
  activeOnly: boolean = true
): Promise<{ data: DashboardAccessFeedResponse }> => {
  return apiClient.get('/dashboard/access-feed', {
    params: { limit, active_only: activeOnly },
  });
};

export const getThreatTrends = (days: number = 7): Promise<{ data: { time_period: string; trend_data: { name: string; SQL_Injection: number; Spam: number; Files: number; Other: number; }[] } }> => {
  return apiClient.get(`/dashboard/threat-trends`, { params: { days } });
};

export type LiveEventsQueryOptions = {
  day?: string;
  before?: string;
  event_types?: string;
  tenant_id?: string;
};

export interface LiveEventsResponsePayload {
  events: any[];
  next_before?: string | null;
  has_more?: boolean;
  day?: string | null;
  before?: string | null;
  event_types?: string;
  scope?: 'admin' | 'viewer';
  limit?: number;
}

export const getLiveEvents = (
  limit: number = 50,
  options: LiveEventsQueryOptions = {}
): Promise<{ data: LiveEventsResponsePayload }> => {
  return apiClient.get(`/dashboard/live-events`, { params: { limit, ...options } });
};

export const getLiveEventDetail = (eventType: string, eventId: string): Promise<{ data: LiveEventDetail }> => {
  return apiClient.get('/dashboard/live-events/detail', {
    params: {
      event_type: eventType,
      event_id: eventId,
    },
  });
};

type DashboardDetailCategory = 'safe' | 'suspicious' | 'blocked';
type DashboardDetailQueryOptions = {
  limit?: number;
  page?: number;
  page_size?: number;
  search?: string;
  category?: DashboardDetailCategory;
};

export const getDashboardFilesScanned = (
  day?: string,
  options: DashboardDetailQueryOptions = {}
): Promise<{ data: { day: string; count: number; total?: number; page?: number; page_size?: number; total_pages?: number; files: DashboardFileScanItem[] } }> => {
  return apiClient.get('/dashboard/files-scanned', { params: { day, ...options } });
};

export const getDashboardSQLQueries = (
  day?: string,
  maliciousOnly: boolean = false,
  options: DashboardDetailQueryOptions = {}
): Promise<{ data: { day: string; count: number; total?: number; page?: number; page_size?: number; total_pages?: number; malicious_only: boolean; queries: DashboardSQLQueryItem[] } }> => {
  return apiClient.get('/dashboard/sql-queries', {
    params: { day, malicious_only: maliciousOnly, ...options },
  });
};

export const getDashboardSpamDetections = (
  day?: string,
  detectedOnly: boolean = true,
  options: DashboardDetailQueryOptions = {}
): Promise<{ data: { day: string; count: number; total?: number; page?: number; page_size?: number; total_pages?: number; detected_only: boolean; detections: DashboardSpamDetectionItem[] } }> => {
  return apiClient.get('/dashboard/spam-detections', {
    params: { day, detected_only: detectedOnly, ...options },
  });
};

export interface CasesQuery {
  page?: number;
  page_size?: number;
  status?: CaseStatus | 'all';
  severity?: CaseSeverity | 'all';
  owner_user_id?: string;
  search_term?: string;
}

export interface CreateCasePayload {
  title: string;
  description?: string;
  severity?: CaseSeverity;
  domain?: string;
  source_type?: string;
  source_id?: string;
  owner_user_id?: string;
  tags?: string[];
  evidence?: Record<string, any>[];
  alert_ids?: string[];
}

export const getCases = (query: CasesQuery = {}): Promise<{ data: SecurityCaseListResponse }> => {
  const params: Record<string, any> = {
    page: query.page ?? 1,
    page_size: query.page_size ?? 20,
    status: query.status && query.status !== 'all' ? query.status : undefined,
    severity: query.severity && query.severity !== 'all' ? query.severity : undefined,
    owner_user_id: query.owner_user_id,
    search_term: query.search_term,
  };
  return apiClient.get('/cases', { params });
};

export const getCaseStats = (): Promise<{ data: SecurityCaseStatsResponse }> => {
  return apiClient.get('/cases/stats');
};

export const getCaseDetail = (caseId: string): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.get(`/cases/${encodeURIComponent(caseId)}`);
};

export const createCase = (payload: CreateCasePayload): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.post('/cases', payload);
};

export const createCaseFromAlert = (alertId: string): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.post(`/cases/from-alert/${encodeURIComponent(alertId)}`);
};

export const updateCaseStatus = (
  caseId: string,
  payload: { status: CaseStatus; note?: string }
): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.patch(`/cases/${encodeURIComponent(caseId)}/status`, payload);
};

export const assignCaseOwner = (
  caseId: string,
  payload: { owner_user_id?: string; note?: string }
): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.patch(`/cases/${encodeURIComponent(caseId)}/assign`, payload);
};

export const addCaseNote = (
  caseId: string,
  payload: { note: string }
): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.post(`/cases/${encodeURIComponent(caseId)}/notes`, payload);
};

export const getCaseNotes = (
  caseId: string,
  limit: number = 200
): Promise<{ data: CaseNotesResponse }> => {
  return apiClient.get(`/cases/${encodeURIComponent(caseId)}/notes`, { params: { limit } });
};

export const getCaseAlertLinks = (
  caseId: string,
  limit: number = 200
): Promise<{ data: CaseAlertLinksResponse }> => {
  return apiClient.get(`/cases/${encodeURIComponent(caseId)}/alerts`, { params: { limit } });
};

export const linkAlertToCase = (
  caseId: string,
  payload: { alert_id: string; note?: string }
): Promise<{ data: SecurityCaseDetail }> => {
  return apiClient.post(`/cases/${encodeURIComponent(caseId)}/alerts`, payload);
};

export const getCaseActivity = (
  caseId: string,
  limit: number = 200
): Promise<{ data: CaseActivityResponse }> => {
  return apiClient.get(`/cases/${encodeURIComponent(caseId)}/activity`, { params: { limit } });
};

export interface InvestigationTimelineQuery {
  limit?: number;
  day?: string;
  start?: string;
  end?: string;
  before?: string;
  event_types?: string;
  entity_key?: string;
  entity_value?: string;
}

export const getInvestigationTimeline = (
  params: InvestigationTimelineQuery = {}
): Promise<{ data: InvestigationTimelineResponse }> => {
  return apiClient.get('/investigation/timeline', { params: { limit: 200, ...params } });
};

export const getMonitoringOverview = (top: number = 20): Promise<{ data: any }> => {
  return apiClient.get('/monitoring/overview', { params: { top } });
};

export const getMonitoringEndpointMetrics = (top: number = 100): Promise<{ data: any }> => {
  return apiClient.get('/monitoring/http/endpoints', { params: { top } });
};

export const getMonitoringWebsocketHealth = (): Promise<{ data: any }> => {
  return apiClient.get('/monitoring/websocket/health');
};

export const getMonitoringFalsePositiveTrends = (
  days: number = 30,
  analystOnly: boolean = true
): Promise<{ data: any }> => {
  return apiClient.get('/monitoring/false-positive-trends', {
    params: { days, analyst_only: analystOnly },
  });
};



export const getAuditEvents = (params: {
  limit?: number;
  offset?: number;
  action?: string;
  actor_user_id?: string;
  start_date?: string;
  end_date?: string;
} = {}): Promise<{ data: AuditListResponse }> => {
  return apiClient.get('/audit', { params });
};

export const getDefenderStatus = (): Promise<{ data: DefenderStatusResponse }> => {
  return apiClient.get('/defender/status');
};

export const getDefenderModels = (params: { domain?: string; stage?: string; limit?: number } = {}): Promise<{ data: DefenderModelInfo[] }> => {
  return apiClient.get('/defender/models', { params });
};

export const getDefenderTrainingJobs = (params: { domain?: string; status?: string; limit?: number } = {}): Promise<{ data: DefenderTrainingJobInfo[] }> => {
  return apiClient.get('/defender/train/jobs', { params });
};

export const getSqlEnforcementConfig = (): Promise<{ data: SqlEnforcementConfigResponse }> => {
  return apiClient.get('/config/sql-enforcement');
};

export const getGovernanceOverview = (): Promise<{ data: GovernanceOverviewResponse }> => {
  return apiClient.get('/config/governance-overview');
};

export const patchSqlEnforcementConfig = (
  payload: SqlEnforcementPatchPayload,
  stepUpToken?: string
): Promise<{ data: SqlEnforcementPatchResponse }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.patch('/config/sql-enforcement', payload, { headers });
};

export const getSpamAutopipelineStatus = (): Promise<{ data: SpamAutopipelineStatusResponse }> => {
  return apiClient.get('/defender/spam-autopipeline/status');
};

export const runSpamAutopipelineNow = (stepUpToken?: string): Promise<{ data: Record<string, any> }> => {
  const headers: Record<string, string> = {};
  if (stepUpToken) headers['X-Step-Up-Token'] = stepUpToken;
  return apiClient.post('/defender/spam-autopipeline/run-now', undefined, { headers });
};

export default apiClient;
