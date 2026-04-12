'use client';

import { useEffect, useRef, useState } from 'react';

/* ── Types ─────────────────────────────────────────────────────────────────── */
type User = {
  username: string;
  role: string;
  created_at?: string;
  updated_at?: string;
};

type Tab = 'secrets' | 'rbac';

const ROLES = ['admin', 'analyst', 'responder', 'readonly'] as const;
type Role = typeof ROLES[number];

const ROLE_COLORS: Record<Role, string> = {
  admin:     'badge-escalated',
  analyst:   'badge-triaged',
  responder: 'badge-new',
  readonly:  'badge-closed',
};

/* ── Secrets config ─────────────────────────────────────────────────────────── */
const SECRET_GROUPS: { label: string; keys: string[] }[] = [
  {
    label: 'Threat intelligence (OpenCTI & AbuseIPDB)',
    keys: [
      'OPENCTI_URL',
      'OPENCTI_TOKEN',
      'OPENCTI_API_KEY',
      'OPENCTI_USER',
      'OPENCTI_EMAIL',
      'OPENCTI_PASSWORD',
      'ABUSEIPDB_API_KEY',
    ],
  },
  {
    label: 'SIEM Connectors',
    keys: ['WAZUH_URL', 'WAZUH_USER', 'WAZUH_PASSWORD', 'SPLUNK_URL', 'SPLUNK_TOKEN', 'SENTINEL_TENANT_ID', 'SENTINEL_CLIENT_ID', 'SENTINEL_CLIENT_SECRET'],
  },
  {
    label: 'Notifications',
    keys: ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'SLACK_WEBHOOK_URL', 'DISCORD_WEBHOOK_URL'],
  },
];

const ALL_KEYS = SECRET_GROUPS.flatMap((g) => g.keys);

/* ── Helpers ────────────────────────────────────────────────────────────────── */
function relTime(ts?: string): string {
  if (!ts) return '—';
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) return '—';
  const diff = Math.max(0, Date.now() - ms);
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}

/* ── Component ──────────────────────────────────────────────────────────────── */
export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('rbac');

  // Secrets state
  const [secretValues, setSecretValues] = useState<Record<string, string>>({});
  const [configured, setConfigured] = useState<Set<string>>(new Set());

  // RBAC state
  const [users, setUsers] = useState<User[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editRoleUser, setEditRoleUser] = useState<User | null>(null);
  const [resetPwUser, setResetPwUser] = useState<User | null>(null);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'analyst' as Role });
  const [modalInput, setModalInput] = useState('');

  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

  const notify = (msg: string, ok = true) => {
    setToast({ msg, ok });
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(null), 3500);
  };

  const jsonPost: RequestInit = { credentials: 'include', headers: { 'content-type': 'application/json' } };

  /* ── Secrets ────────────────────────────────────────────────────────────── */
  const loadSecrets = async () => {
    const res = await fetch('/api/admin/secrets', { credentials: 'include', cache: 'no-store' });
    const data = await res.json();
    if (Array.isArray(data)) setConfigured(new Set(data.map((d: { key: string }) => d.key)));
    else notify(data.detail || 'Failed to load secrets', false);
  };

  const saveSecret = async (key: string) => {
    const value = secretValues[key]?.trim();
    if (!value) { notify('Enter a value first', false); return; }
    const res = await fetch('/api/admin/secrets', {
      method: 'PUT',
      ...jsonPost,
      body: JSON.stringify({ key, value }),
    });
    const data = await res.json();
    if (res.ok) {
      setConfigured((prev) => new Set([...prev, key]));
      setSecretValues((prev) => ({ ...prev, [key]: '' }));
      notify(`${key} saved`);
    } else {
      notify(data.detail || `Failed to save ${key}`, false);
    }
  };

  /* ── Users/RBAC ─────────────────────────────────────────────────────────── */
  const loadUsers = async () => {
    const res = await fetch('/api/admin/users', { credentials: 'include', cache: 'no-store' });
    const data = await res.json();
    if (Array.isArray(data)) setUsers(data);
    else notify(data.detail || 'Failed to load users', false);
  };

  const createUser = async () => {
    const { username, password, role } = newUser;
    if (!username.trim() || !password.trim()) { notify('Username and password required', false); return; }
    const res = await fetch('/api/admin/users', {
      method: 'POST',
      ...jsonPost,
      body: JSON.stringify({ username: username.trim(), password, role }),
    });
    const data = await res.json();
    if (res.ok) {
      notify(`User '${username}' created`);
      setShowCreateModal(false);
      setNewUser({ username: '', password: '', role: 'analyst' });
      loadUsers();
    } else {
      notify(data.detail || 'Failed to create user', false);
    }
  };

  const updateRole = async () => {
    if (!editRoleUser) return;
    const res = await fetch(`/api/admin/users/${encodeURIComponent(editRoleUser.username)}`, {
      method: 'PUT',
      ...jsonPost,
      body: JSON.stringify({ role: modalInput }),
    });
    const data = await res.json();
    if (res.ok) {
      notify(`Role updated → ${modalInput}`);
      setEditRoleUser(null);
      setModalInput('');
      loadUsers();
    } else {
      notify(data.detail || 'Failed to update role', false);
    }
  };

  const resetPassword = async () => {
    if (!resetPwUser) return;
    const res = await fetch(`/api/admin/users/${encodeURIComponent(resetPwUser.username)}`, {
      method: 'PUT',
      ...jsonPost,
      body: JSON.stringify({ password: modalInput }),
    });
    const data = await res.json();
    if (res.ok) {
      notify(`Password updated for ${resetPwUser.username}`);
      setResetPwUser(null);
      setModalInput('');
    } else {
      notify(data.detail || 'Failed to update password', false);
    }
  };

  const deleteUser = async (username: string) => {
    const res = await fetch(`/api/admin/users/${encodeURIComponent(username)}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    const data = await res.json();
    if (res.ok) {
      notify(`User '${username}' deleted`);
      loadUsers();
    } else {
      notify(data.detail || 'Failed to delete user', false);
    }
  };

  /* ── Bootstrap ──────────────────────────────────────────────────────────── */
  useEffect(() => {
    void loadSecrets();
    void loadUsers();
  }, []);

  /* ── Tab nav ─────────────────────────────────────────────────────────────── */
  const tabStyle = (t: Tab): React.CSSProperties => ({
    padding: '8px 16px',
    cursor: 'pointer',
    borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
    color: tab === t ? 'var(--text-primary)' : 'var(--text-secondary)',
    fontWeight: tab === t ? 600 : 400,
    fontSize: 13,
    background: 'none',
    border: 'none',
    borderRadius: 0,
  });

  return (
    <div>
      <div className="page-hd">
        <h1>Admin</h1>
        <div className="flex gap-2">
          <button type="button" onClick={() => { void loadUsers(); void loadSecrets(); }}>↻ Refresh</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', marginBottom: 20 }}>
        <button style={tabStyle('rbac')} onClick={() => setTab('rbac')}>Users &amp; RBAC</button>
        <button style={tabStyle('secrets')} onClick={() => setTab('secrets')}>
          API Secrets &nbsp;<span className="badge badge-new" style={{ fontSize: 10 }}>{configured.size}/{ALL_KEYS.length}</span>
        </button>
      </div>

      {/* ── RBAC Tab ──────────────────────────────────────────────────────── */}
      {tab === 'rbac' && (
        <div>
          <div className="page-hd" style={{ marginBottom: 12 }}>
            <div className="page-meta">{users.length} user{users.length !== 1 ? 's' : ''} · Role matrix: admin → analyst → responder → readonly</div>
            <button className="btn-primary" onClick={() => setShowCreateModal(true)}>+ New User</button>
          </div>

          {/* Role legend */}
          <div className="flex gap-2 mb-4" style={{ flexWrap: 'wrap' }}>
            {ROLES.map((r) => (
              <div key={r} className="flex items-center gap-1" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                <span className={`badge ${ROLE_COLORS[r]}`}>{r}</span>
                <span>·</span>
                <span>
                  {r === 'admin' && 'Full access, manage users & secrets'}
                  {r === 'analyst' && 'Cases, alerts triage, OpenCTI sync (server)'}
                  {r === 'responder' && 'Alerts triage, containment actions'}
                  {r === 'readonly' && 'Read-only across all resources'}
                </span>
              </div>
            ))}
          </div>

          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th className="hide-mobile">Created</th>
                <th className="hide-mobile">Last updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username}>
                  <td style={{ fontWeight: 500 }}>{u.username}</td>
                  <td><span className={`badge ${ROLE_COLORS[u.role as Role] || 'badge-info'}`}>{u.role}</span></td>
                  <td className="text-muted hide-mobile">{relTime(u.created_at)}</td>
                  <td className="text-muted hide-mobile">{relTime(u.updated_at)}</td>
                  <td>
                    <div className="flex gap-1">
                      <button onClick={() => { setEditRoleUser(u); setModalInput(u.role); }}>Change Role</button>
                      <button onClick={() => { setResetPwUser(u); setModalInput(''); }}>Reset Password</button>
                      <button className="btn-danger" onClick={() => deleteUser(u.username)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
              {!users.length && (
                <tr><td colSpan={5}><div className="empty-state">No users found.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Secrets Tab ───────────────────────────────────────────────────── */}
      {tab === 'secrets' && (
        <div>
          {SECRET_GROUPS.map((group) => (
            <div key={group.label} className="card mb-4">
              <div className="card-header">
                <span className="card-title">{group.label}</span>
                <span className="text-muted" style={{ fontSize: 11 }}>
                  {group.keys.filter((k) => configured.has(k)).length} / {group.keys.length} configured
                </span>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: 280 }}>Key</th>
                    <th style={{ width: 110 }}>Status</th>
                    <th>New Value</th>
                    <th style={{ width: 80 }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {group.keys.map((k) => (
                    <tr key={k}>
                      <td className="mono">{k}</td>
                      <td>
                        {configured.has(k)
                          ? <span className="badge badge-closed">Configured</span>
                          : <span className="badge badge-new">Not set</span>}
                      </td>
                      <td>
                        <input
                          type="password"
                          placeholder={configured.has(k) ? '(leave blank to keep)' : 'Enter value…'}
                          value={secretValues[k] || ''}
                          onChange={(e) => setSecretValues((prev) => ({ ...prev, [k]: e.target.value }))}
                          style={{ width: '100%', maxWidth: 400 }}
                          autoComplete="off"
                        />
                      </td>
                      <td><button className="btn-primary" onClick={() => saveSecret(k)}>Save</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}

      {/* ── Modals ────────────────────────────────────────────────────────── */}

      {/* Create user modal */}
      {showCreateModal && (
        <div className="modal-backdrop" onClick={() => setShowCreateModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Create New User</div>
            <div className="form-row">
              <div>
                <label>Username</label>
                <input autoFocus value={newUser.username} onChange={(e) => setNewUser((p) => ({ ...p, username: e.target.value }))} className="w-full" placeholder="john.doe" />
              </div>
              <div>
                <label>Password</label>
                <input type="password" value={newUser.password} onChange={(e) => setNewUser((p) => ({ ...p, password: e.target.value }))} className="w-full" placeholder="••••••••" autoComplete="new-password" />
              </div>
              <div>
                <label>Role</label>
                <select value={newUser.role} onChange={(e) => setNewUser((p) => ({ ...p, role: e.target.value as Role }))} className="w-full">
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button className="btn-primary" onClick={createUser}>Create User</button>
            </div>
          </div>
        </div>
      )}

      {/* Change role modal */}
      {editRoleUser && (
        <div className="modal-backdrop" onClick={() => setEditRoleUser(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Change Role — {editRoleUser.username}</div>
            <label>New Role</label>
            <select value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full">
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
            <div className="modal-footer">
              <button onClick={() => setEditRoleUser(null)}>Cancel</button>
              <button className="btn-primary" onClick={updateRole}>Update Role</button>
            </div>
          </div>
        </div>
      )}

      {/* Reset password modal */}
      {resetPwUser && (
        <div className="modal-backdrop" onClick={() => setResetPwUser(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Reset Password — {resetPwUser.username}</div>
            <label>New Password</label>
            <input autoFocus type="password" value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full" placeholder="••••••••" autoComplete="new-password" />
            <div className="modal-footer">
              <button onClick={() => setResetPwUser(null)}>Cancel</button>
              <button className="btn-primary" onClick={resetPassword}>Update Password</button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className={`toast ${toast.ok ? 'success' : 'error'}`}>{toast.msg}</div>}
    </div>
  );
}
