import React from 'react';
import NotificationToast from './components/common/NotificationToast';
import AppShell from './components/layout/AppShell';
import { WebSocketProvider } from './contexts/WebSocketContext';
import {
  clearAuthSession,
  getAccessToken,
  getAuthUser,
  getCurrentUser,
  login,
  setAuthSession,
} from './lib/apiClient';
import { useAppStore, type Page } from './store/appStore';
import { canAccessPage, normalizeRole, type UserRole } from './features/console/consoleConfig';

const DashboardHomePage = React.lazy(() => import('./features/console/DashboardHomePage'));
const AlertsWorkspacePage = React.lazy(() => import('./features/console/AlertsWorkspacePage'));
const CasesPage = React.lazy(() => import('./features/console/CasesPage'));
const InvestigationPage = React.lazy(() => import('./features/console/InvestigationPage'));
const SQLSecurityPage = React.lazy(() => import('./features/console/SQLSecurityPage'));
const FileSecurityPage = React.lazy(() => import('./features/console/FileSecurityPage'));
const EmailSecurityPage = React.lazy(() => import('./features/console/EmailSecurityPage'));
const PlatformHealthPage = React.lazy(() => import('./features/console/PlatformHealthPage'));
const AuditLogPage = React.lazy(() => import('./features/console/AuditLogPage'));
const ModelOpsPage = React.lazy(() => import('./features/console/ModelOpsPage'));
const PolicyRulesPage = React.lazy(() => import('./features/console/PolicyRulesPage'));
const UserManagementPage = React.lazy(() => import('./features/users/UserManagementPage'));

type DashboardPageLink = Exclude<Page, 'dashboard'>;

function App() {
  const { activePage, setActivePage } = useAppStore();
  const [isAuthenticated, setIsAuthenticated] = React.useState<boolean>(false);
  const [authResolved, setAuthResolved] = React.useState<boolean>(false);
  const [userRole, setUserRole] = React.useState<UserRole>(() => normalizeRole(getAuthUser()?.role));
  const [email, setEmail] = React.useState<string>(() => getAuthUser()?.email || 'admin@example.com');
  const [password, setPassword] = React.useState<string>('');
  const [authError, setAuthError] = React.useState<string>('');
  const [authLoading, setAuthLoading] = React.useState<boolean>(false);

  React.useEffect(() => {
    let mounted = true;
    const bootstrapAuth = async () => {
      const token = getAccessToken();
      if (!token) {
        if (mounted) {
          setIsAuthenticated(false);
          setAuthResolved(true);
        }
        return;
      }
      try {
        const me = await getCurrentUser();
        if (!mounted) return;
        setAuthSession(token, me.data);
        setEmail(me.data.email);
        const normalizedRole = normalizeRole(me.data.role);
        setUserRole(normalizedRole);
        if (!canAccessPage(normalizedRole, activePage)) {
          setActivePage('dashboard');
        }
        setIsAuthenticated(true);
      } catch {
        if (!mounted) return;
        clearAuthSession();
        setUserRole('viewer');
        setIsAuthenticated(false);
      } finally {
        if (mounted) setAuthResolved(true);
      }
    };
    void bootstrapAuth();
    return () => {
      mounted = false;
    };
  }, [activePage, setActivePage]);

  React.useEffect(() => {
    const onAuthChanged = () => {
      const hasToken = Boolean(getAccessToken());
      setIsAuthenticated(hasToken);
      setAuthResolved(true);
      if (!hasToken) {
        setUserRole('viewer');
        setActivePage('dashboard');
        return;
      }
      const user = getAuthUser();
      if (user?.email) setEmail(user.email);
      const normalizedRole = normalizeRole(user?.role);
      setUserRole(normalizedRole);
      if (!canAccessPage(normalizedRole, activePage)) {
        setActivePage('dashboard');
      }
    };
    window.addEventListener('auth:changed', onAuthChanged);
    return () => window.removeEventListener('auth:changed', onAuthChanged);
  }, [activePage, setActivePage]);

  const renderActivePage = () => {
    if (!canAccessPage(userRole, activePage)) {
      return (
        <div className="rounded-2xl border border-border-dark/70 bg-dark-secondary/80 p-6 text-sm text-text-secondary">
          You do not have permission to access this page.
        </div>
      );
    }

    const openDashboardPage = (page: DashboardPageLink) => {
      if (canAccessPage(userRole, page)) {
        setActivePage(page);
      }
    };

    let pageComponent: React.ReactNode;
    switch (activePage) {
      case 'dashboard':
        pageComponent = <DashboardHomePage role={userRole} onOpenPage={openDashboardPage} />;
        break;
      case 'alerts':
        pageComponent = <AlertsWorkspacePage role={userRole} />;
        break;
      case 'cases':
        pageComponent = <CasesPage role={userRole} />;
        break;
      case 'investigation':
        pageComponent = <InvestigationPage role={userRole} />;
        break;
      case 'sqlSecurity':
        pageComponent = <SQLSecurityPage role={userRole} />;
        break;
      case 'fileSecurity':
        pageComponent = <FileSecurityPage role={userRole} />;
        break;
      case 'emailSecurity':
        pageComponent = <EmailSecurityPage role={userRole} />;
        break;
      case 'platformHealth':
        pageComponent = <PlatformHealthPage role={userRole} />;
        break;
      case 'auditLog':
        pageComponent = <AuditLogPage role={userRole} />;
        break;
      case 'modelOps':
        pageComponent = <ModelOpsPage role={userRole} />;
        break;
      case 'policyRules':
        pageComponent = <PolicyRulesPage role={userRole} />;
        break;
      case 'userManagement':
        pageComponent = <UserManagementPage />;
        break;
      default:
        pageComponent = <DashboardHomePage role={userRole} onOpenPage={openDashboardPage} />;
        break;
    }

    return (
      <React.Suspense
        fallback={
          <div className="rounded-2xl border border-border-dark/70 bg-dark-secondary/80 p-6 text-sm text-text-secondary">
            Loading workspace...
          </div>
        }
      >
        {pageComponent}
      </React.Suspense>
    );
  };

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const response = await login(email.trim(), password);
      setPassword('');
      const normalizedRole = normalizeRole(response.user.role);
      setUserRole(normalizedRole);
      setIsAuthenticated(true);
      setAuthResolved(true);
      if (!canAccessPage(normalizedRole, activePage)) {
        setActivePage('dashboard');
      }
    } catch (error: any) {
      setAuthError(error?.response?.data?.detail || 'Login failed');
      setIsAuthenticated(false);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    clearAuthSession();
    setPassword('');
    setUserRole('viewer');
    setIsAuthenticated(false);
    setActivePage('dashboard');
  };

  if (!authResolved) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#0a1220] px-4 text-sm text-text-secondary">
        Checking secure session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#07101d] px-4">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md rounded-3xl border border-border-dark/70 bg-[#0e1727] p-8 shadow-[0_24px_80px_rgba(0,0,0,0.35)]"
        >
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">Security operations login</p>
          <h1 className="mt-3 text-3xl font-semibold text-white">Sign in to Middleware Security</h1>
          <p className="mt-2 text-sm text-text-secondary">
            Role-aware console for detection, investigation, and governed runtime defense.
          </p>
          <div className="mt-6 space-y-4">
            <div>
              <label className="mb-2 block text-sm text-text-secondary">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-2xl border border-border-dark/70 bg-dark-tertiary px-4 py-3 text-white outline-none placeholder:text-text-secondary focus:border-cyan-400/50"
                required
              />
            </div>
            <div>
              <label className="mb-2 block text-sm text-text-secondary">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-2xl border border-border-dark/70 bg-dark-tertiary px-4 py-3 text-white outline-none placeholder:text-text-secondary focus:border-cyan-400/50"
                required
              />
            </div>
            {authError ? <p className="text-sm text-red-300">{authError}</p> : null}
            <button
              type="submit"
              disabled={authLoading}
              className="w-full rounded-2xl bg-cyan-600 px-4 py-3 font-medium text-white transition hover:bg-cyan-500 disabled:opacity-60"
            >
              {authLoading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    );
  }

  return (
    <WebSocketProvider>
      <NotificationToast />
      <AppShell role={userRole} onLogout={handleLogout}>
        {renderActivePage()}
      </AppShell>
    </WebSocketProvider>
  );
}

export default App;
