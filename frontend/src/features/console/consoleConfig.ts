import type { Page } from '../../store/appStore';

export type UserRole = 'admin' | 'analyst' | 'reviewer' | 'viewer';

export const normalizeRole = (value: string | null | undefined): UserRole => {
  const role = String(value || '').toLowerCase();
  if (role === 'admin') return 'admin';
  if (role === 'analyst') return 'analyst';
  if (role === 'reviewer') return 'reviewer';
  return 'viewer';
};

export const ALLOWED_PAGES_BY_ROLE: Record<UserRole, Page[]> = {
  admin: [
    'dashboard',
    'alerts',
    'cases',
    'investigation',
    'sqlSecurity',
    'fileSecurity',
    'emailSecurity',
    'platformHealth',
    'auditLog',
    'modelOps',
    'policyRules',
    'userManagement',
  ],
  analyst: [
    'dashboard',
    'alerts',
    'cases',
    'investigation',
    'sqlSecurity',
    'fileSecurity',
    'emailSecurity',
    'platformHealth',
    'modelOps',
  ],
  reviewer: [
    'dashboard',
    'platformHealth',
    'modelOps',
  ],
  viewer: [
    'dashboard',
    'sqlSecurity',
    'fileSecurity',
    'emailSecurity',
  ],
};

export const canAccessPage = (role: UserRole, page: Page): boolean => ALLOWED_PAGES_BY_ROLE[role].includes(page);

export const PAGE_META: Record<Page, { title: string; description: string; label: string }> = {
  dashboard: {
    title: 'Dashboard',
    label: 'Dashboard',
    description: 'Role-aware security posture, triage, and operations overview.',
  },
  alerts: {
    title: 'Alerts Workspace',
    label: 'Alerts',
    description: 'Triage actionable signals, inspect evidence, and initiate cases.',
  },
  cases: {
    title: 'Cases',
    label: 'Cases',
    description: 'Track investigation ownership, notes, and linked evidence over time.',
  },
  investigation: {
    title: 'Investigation',
    label: 'Investigation',
    description: 'Correlate live activity, alerts, and evidence across domains.',
  },
  sqlSecurity: {
    title: 'SQL Security',
    label: 'SQL Security',
    description: 'Runtime SQL defense, anomaly scoring, and query analysis operations.',
  },
  fileSecurity: {
    title: 'File Security',
    label: 'File Security',
    description: 'File inspection workflows, scanner posture, and upload risk review.',
  },
  emailSecurity: {
    title: 'Email Security',
    label: 'Email Security',
    description: 'Phishing and spam review with explainable classifier evidence.',
  },
  platformHealth: {
    title: 'Platform Health',
    label: 'Platform Health',
    description: 'Observe queueing, API responsiveness, websocket status, and model runtime health.',
  },
  auditLog: {
    title: 'Audit Log',
    label: 'Audit Log',
    description: 'Review who changed what, when, and whether the action succeeded.',
  },
  modelOps: {
    title: 'Model Ops',
    label: 'Model Ops',
    description: 'Review feedback, training jobs, and registered defender models.',
  },
  policyRules: {
    title: 'Policy & Rules',
    label: 'Policy & Rules',
    description: 'Unified governance surface for SQL, file, email, suppressions, and change history.',
  },
  userManagement: {
    title: 'User Management',
    label: 'User Management',
    description: 'Create users, manage roles, and control account access.',
  },
};

export const NAV_PAGE_ORDER: Page[] = [
  'dashboard',
  'alerts',
  'cases',
  'investigation',
  'sqlSecurity',
  'fileSecurity',
  'emailSecurity',
  'platformHealth',
  'auditLog',
  'modelOps',
  'policyRules',
  'userManagement',
];
