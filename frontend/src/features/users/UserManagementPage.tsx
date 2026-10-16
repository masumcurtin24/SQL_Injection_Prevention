import React from 'react';

import { useNotification } from '../../contexts/useNotification';
import {
  createUser,
  deleteUser,
  getAccessToken,
  getAuthUser,
  getCurrentUser,
  getTenants,
  getUsers,
  setAuthSession,
  updateUser,
  type AdminUser,
  type TenantSummary,
} from '../../lib/apiClient';
import { useAppStore } from '../../store/appStore';
import { formatTimestamp } from '../../lib/dateUtils';

type UserRole = 'admin' | 'analyst' | 'reviewer' | 'viewer';

interface RowDraft {
  tenant_id: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  password: string;
}

const UserManagementPage: React.FC = () => {
  const { showNotification } = useNotification();
  const setActivePage = useAppStore((state) => state.setActivePage);
  const selectedTenant = useAppStore((state) => state.selectedTenant);
  const tenantOptions = useAppStore((state) => state.tenantOptions);
  const setTenantOptions = useAppStore((state) => state.setTenantOptions);
  const currentUserId = String(getAuthUser()?.id || '');
  const currentUserRole = String(getAuthUser()?.role || 'viewer').toLowerCase();

  const [rows, setRows] = React.useState<AdminUser[]>([]);
  const [drafts, setDrafts] = React.useState<Record<string, RowDraft>>({});
  const [loading, setLoading] = React.useState(false);
  const [savingId, setSavingId] = React.useState<string | null>(null);
  const [deletingId, setDeletingId] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState('');

  const [newFullName, setNewFullName] = React.useState('');
  const [newEmail, setNewEmail] = React.useState('');
  const [newPassword, setNewPassword] = React.useState('');
  const [newRole, setNewRole] = React.useState<UserRole>('viewer');
  const [newActive, setNewActive] = React.useState(true);
  const [newTenantId, setNewTenantId] = React.useState('');
  const [creating, setCreating] = React.useState(false);

  const isAdmin = currentUserRole === 'admin';

  React.useEffect(() => {
    if (!newTenantId && selectedTenant) {
      setNewTenantId(selectedTenant);
    }
  }, [newTenantId, selectedTenant]);

  React.useEffect(() => {
    let cancelled = false;
    const loadTenants = async () => {
      if (tenantOptions.length > 0) return;
      try {
        const res = await getTenants();
        if (cancelled) return;
        const options = Array.isArray(res.data?.tenants)
          ? res.data.tenants.map((row: TenantSummary) => ({
              id: String(row.id || ''),
              slug: String(row.slug || ''),
              name: String(row.name || row.slug || row.id),
              is_active: Boolean(row.is_active),
            }))
          : [];
        setTenantOptions(options);
        if (!newTenantId && options[0]?.id) {
          setNewTenantId(options[0].id);
        }
      } catch {
        // Ignore; user APIs still function with current tenant defaulting.
      }
    };
    void loadTenants();
    return () => {
      cancelled = true;
    };
  }, [newTenantId, setTenantOptions, tenantOptions.length]);

  const loadUsers = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await getUsers();
      const list = Array.isArray(res.data?.users) ? res.data.users : [];
      setRows(list);
      const nextDrafts: Record<string, RowDraft> = {};
      for (const user of list) {
        nextDrafts[user.id] = {
          tenant_id: String(user.tenant_id || selectedTenant || ''),
          full_name: String(user.full_name || ''),
          role: (user.role || 'viewer') as UserRole,
          is_active: Boolean(user.is_active),
          password: '',
        };
      }
      setDrafts(nextDrafts);
    } catch {
      showNotification('Failed to load users', 'error');
      setRows([]);
      setDrafts({});
    } finally {
      setLoading(false);
    }
  }, [selectedTenant, showNotification]);

  React.useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const visibleRows = React.useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return rows;
    return rows.filter((u) => {
      return (
        String(u.email || '').toLowerCase().includes(term) ||
        String(u.full_name || '').toLowerCase().includes(term) ||
        String(u.role || '').toLowerCase().includes(term) ||
        String(u.id || '').toLowerCase().includes(term)
      );
    });
  }, [rows, search]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const fullName = newFullName.trim();
    const email = newEmail.trim().toLowerCase();
    if (!fullName || !email || !newPassword.trim()) {
      showNotification('Full name, email and password are required', 'error');
      return;
    }
    setCreating(true);
    try {
      await createUser({
        email,
        tenant_id: newTenantId || selectedTenant || undefined,
        full_name: fullName,
        password: newPassword.trim(),
        role: newRole,
        is_active: newActive,
      });
      setNewFullName('');
      setNewEmail('');
      setNewPassword('');
      setNewRole('viewer');
      setNewActive(true);
      setNewTenantId(selectedTenant || '');
      showNotification('User created', 'success');
      await loadUsers();
    } catch (error: any) {
      const detail = String(error?.response?.data?.detail || '');
      showNotification(detail || 'Failed to create user', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleSaveRow = async (user: AdminUser) => {
    const draft = drafts[user.id];
    if (!draft) return;
    const payload: { tenant_id?: string; full_name?: string | null; role?: UserRole; is_active?: boolean; password?: string } = {};

    const normalizedTenantId = String(draft.tenant_id || '').trim();
    const currentTenantId = String(user.tenant_id || '').trim();
    if (normalizedTenantId && normalizedTenantId !== currentTenantId) {
      payload.tenant_id = normalizedTenantId;
    }
    const normalizedFullName = draft.full_name.trim();
    const currentFullName = String(user.full_name || '').trim();
    if (normalizedFullName !== currentFullName) {
      payload.full_name = normalizedFullName || null;
    }
    if (draft.role !== user.role) {
      payload.role = draft.role;
    }
    if (Boolean(draft.is_active) !== Boolean(user.is_active)) {
      payload.is_active = Boolean(draft.is_active);
    }
    if (draft.password.trim()) {
      payload.password = draft.password.trim();
    }
    if (
      payload.full_name === undefined &&
      !payload.tenant_id &&
      !payload.role &&
      payload.is_active === undefined &&
      !payload.password
    ) {
      showNotification('No changes to save', 'info');
      return;
    }

    setSavingId(user.id);
    try {
      const res = await updateUser(user.id, payload);
      const updated = res.data;
      setRows((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
      setDrafts((prev) => ({
        ...prev,
        [user.id]: {
          full_name: String(updated.full_name || ''),
          tenant_id: String(updated.tenant_id || selectedTenant || ''),
          role: (updated.role || 'viewer') as UserRole,
          is_active: Boolean(updated.is_active),
          password: '',
        },
      }));
      showNotification('User updated', 'success');

      if (user.id === currentUserId) {
        try {
          const me = await getCurrentUser();
          const accessToken = getAccessToken();
          if (accessToken) {
            setAuthSession(accessToken, me.data);
          }
        } catch {
          // If current session became invalid, interceptor will handle sign-out.
        }
        const newRole = String(updated.role || '').toLowerCase();
        if (newRole !== 'admin') {
          setActivePage('dashboard');
          showNotification('Your role changed. Admin-only pages are now hidden.', 'info');
        }
      }
    } catch (error: any) {
      const detail = String(error?.response?.data?.detail || '');
      showNotification(detail || 'Failed to update user', 'error');
    } finally {
      setSavingId(null);
    }
  };

  const handleDeleteRow = async (user: AdminUser) => {
    if (user.id === currentUserId) {
      showNotification('You cannot delete your own account.', 'error');
      return;
    }

    const confirmed = window.confirm(
      `Delete user "${user.full_name || user.email}" (${user.email})?\n\nThis action cannot be undone.`
    );
    if (!confirmed) return;

    setDeletingId(user.id);
    try {
      await deleteUser(user.id);
      showNotification('User deleted', 'success');
      await loadUsers();
    } catch (error: any) {
      const detail = String(error?.response?.data?.detail || '');
      showNotification(detail || 'Failed to delete user', 'error');
    } finally {
      setDeletingId(null);
    }
  };

  if (!isAdmin) {
    return (
      <div className="p-4 sm:p-6 md:p-8 text-white">
        <div className="w-full max-w-3xl mx-auto bg-gray-900/70 border border-gray-700/60 rounded-xl p-6">
          <h1 className="text-2xl font-bold">User Management</h1>
          <p className="text-gray-300 mt-2">Admin role is required to manage users.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 md:p-8 text-white">
      <div className="w-full max-w-6xl mx-auto space-y-4">
        <div className="bg-gray-900/70 border border-gray-700/60 rounded-xl p-6">
          <h1 className="text-2xl sm:text-3xl font-bold">User Management</h1>
          <p className="text-sm text-gray-300 mt-1">
            Create users and switch roles from the UI. Changes apply immediately.
          </p>
        </div>

        <div className="bg-gray-900/70 border border-gray-700/60 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-3">Create User</h2>
          <form className="grid grid-cols-1 md:grid-cols-7 gap-2" onSubmit={handleCreate}>
            <input
              type="text"
              value={newFullName}
              onChange={(e) => setNewFullName(e.target.value)}
              placeholder="Full name"
              className="md:col-span-2 px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
              required
            />
            <input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="email@example.com"
              className="md:col-span-2 px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
              required
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="password (min 8 chars)"
              className="px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
              required
            />
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as UserRole)}
              className="px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
            >
              <option value="viewer">viewer</option>
              <option value="reviewer">reviewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
            <select
              value={newTenantId}
              onChange={(e) => setNewTenantId(e.target.value)}
              className="px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
            >
              {tenantOptions.length > 0 ? (
                tenantOptions.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </option>
                ))
              ) : (
                <option value={selectedTenant || ''}>{selectedTenant || 'Current tenant'}</option>
              )}
            </select>
            <label className="inline-flex items-center gap-2 px-3 py-2 rounded bg-gray-800 border border-gray-700 text-sm">
              <input
                type="checkbox"
                checked={newActive}
                onChange={(e) => setNewActive(e.target.checked)}
              />
              Active
            </label>
              <button
                type="submit"
                disabled={creating}
                className="md:col-span-7 px-3 py-2 rounded border border-cyan-500/50 text-cyan-200 hover:border-cyan-300 disabled:opacity-50 text-sm"
              >
                {creating ? 'Creating...' : 'Create User'}
              </button>
          </form>
        </div>

        <div className="bg-gray-900/70 border border-gray-700/60 rounded-xl p-6">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
            <h2 className="text-lg font-semibold">Users</h2>
            <div className="flex items-center gap-2">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by email/role/id"
                className="px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white outline-none focus:border-cyan-500 text-sm"
              />
              <button
                type="button"
                onClick={() => {
                  void loadUsers();
                }}
                disabled={loading}
                className="px-3 py-2 rounded border border-gray-600 hover:border-gray-400 disabled:opacity-50 text-sm"
              >
                Refresh
              </button>
            </div>
          </div>

          {loading ? (
            <p className="text-sm text-gray-300">Loading users...</p>
          ) : visibleRows.length === 0 ? (
            <p className="text-sm text-gray-300">No users found.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="text-gray-300">
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 pr-3">Full Name</th>
                    <th className="text-left py-2 pr-3">Email</th>
                    <th className="text-left py-2 pr-3">Tenant</th>
                    <th className="text-left py-2 pr-3">Role</th>
                    <th className="text-left py-2 pr-3">Active</th>
                    <th className="text-left py-2 pr-3">Last Login</th>
                    <th className="text-left py-2 pr-3">Reset Password</th>
                    <th className="text-left py-2 pr-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRows.map((user) => {
                    const draft = drafts[user.id] || {
                      tenant_id: String(user.tenant_id || selectedTenant || ''),
                      full_name: String(user.full_name || ''),
                      role: (user.role || 'viewer') as UserRole,
                      is_active: Boolean(user.is_active),
                      password: '',
                    };
                    const isDirty =
                      String(draft.tenant_id || '').trim() !== String(user.tenant_id || '').trim() ||
                      draft.full_name.trim() !== String(user.full_name || '').trim() ||
                      draft.role !== user.role ||
                      Boolean(draft.is_active) !== Boolean(user.is_active) ||
                      Boolean(draft.password.trim());
                    return (
                      <tr key={user.id} className="border-b border-gray-800/80">
                        <td className="py-2 pr-3">
                          <input
                            type="text"
                            value={draft.full_name}
                            onChange={(e) =>
                              setDrafts((prev) => ({
                                ...prev,
                                [user.id]: { ...draft, full_name: e.target.value },
                              }))
                            }
                            placeholder="Full name"
                            className="w-full px-2 py-1 rounded bg-gray-800 border border-gray-700 text-white text-sm"
                          />
                        </td>
                        <td className="py-2 pr-3">
                          <div className="text-gray-100">{user.email}</div>
                          <div className="text-[11px] text-gray-500">{user.id}</div>
                        </td>
                        <td className="py-2 pr-3">
                          <select
                            value={draft.tenant_id}
                            onChange={(e) =>
                              setDrafts((prev) => ({
                                ...prev,
                                [user.id]: { ...draft, tenant_id: e.target.value },
                              }))
                            }
                            className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-white text-sm"
                          >
                            {tenantOptions.length > 0 ? (
                              tenantOptions.map((tenant) => (
                                <option key={tenant.id} value={tenant.id}>
                                  {tenant.name}
                                </option>
                              ))
                            ) : (
                              <option value={draft.tenant_id}>{draft.tenant_id || 'Current'}</option>
                            )}
                          </select>
                        </td>
                        <td className="py-2 pr-3">
                          <select
                            value={draft.role}
                            onChange={(e) =>
                              setDrafts((prev) => ({
                                ...prev,
                                [user.id]: { ...draft, role: e.target.value as UserRole },
                              }))
                            }
                            className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-white text-sm"
                          >
                            <option value="viewer">viewer</option>
                            <option value="reviewer">reviewer</option>
                            <option value="analyst">analyst</option>
                            <option value="admin">admin</option>
                          </select>
                        </td>
                        <td className="py-2 pr-3">
                          <label className="inline-flex items-center gap-2 text-sm">
                            <input
                              type="checkbox"
                              checked={Boolean(draft.is_active)}
                              onChange={(e) =>
                                setDrafts((prev) => ({
                                  ...prev,
                                  [user.id]: { ...draft, is_active: e.target.checked },
                                }))
                              }
                            />
                            {draft.is_active ? 'Yes' : 'No'}
                          </label>
                        </td>
                        <td className="py-2 pr-3 text-gray-300">
                          {user.last_login_at ? formatTimestamp(user.last_login_at) : '-'}
                        </td>
                        <td className="py-2 pr-3">
                          <input
                            type="password"
                            value={draft.password}
                            onChange={(e) =>
                              setDrafts((prev) => ({
                                ...prev,
                                [user.id]: { ...draft, password: e.target.value },
                              }))
                            }
                            placeholder="optional"
                            className="px-2 py-1 rounded bg-gray-800 border border-gray-700 text-white text-sm"
                          />
                        </td>
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                void handleSaveRow(user);
                              }}
                              disabled={!isDirty || savingId === user.id || deletingId === user.id}
                              className="px-3 py-1.5 rounded border border-cyan-500/50 text-cyan-200 hover:border-cyan-300 disabled:opacity-50 text-sm"
                            >
                              {savingId === user.id ? 'Saving...' : 'Save'}
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                void handleDeleteRow(user);
                              }}
                              disabled={user.id === currentUserId || deletingId === user.id || savingId === user.id}
                              className="px-3 py-1.5 rounded border border-red-500/50 text-red-200 hover:border-red-300 disabled:opacity-50 text-sm"
                              title={user.id === currentUserId ? 'You cannot delete your own account' : 'Delete this user'}
                            >
                              {deletingId === user.id ? 'Deleting...' : 'Delete'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserManagementPage;
