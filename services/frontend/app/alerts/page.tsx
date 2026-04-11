'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useEffect, useRef, useState } from 'react';

const VIEW_PRESETS_KEY = 'sirp_alert_view_presets_v1';

type ViewPreset = { name: string; filter: string; sev: string; status: string };

type AgentBlock = { id?: string; name?: string; ip?: string };
type RuleRef = {
  id?: string | number;
  level?: number;
  groups?: string[] | string;
  description?: string;
};
type Observable = { type?: string; value?: string };

type Alert = {
  id: string;
  severity?: string;
  source?: string;
  status?: string;
  title?: string;
  description?: string;
  summary?: string;
  tags?: string[];
  assigned_to?: string;
  created_at?: string;
  risk_score?: number;
  agent?: AgentBlock;
  rule_ref?: RuleRef;
  location?: string;
  observables?: Observable[];
  raw?: unknown;
};

function agentLine(a?: AgentBlock): string {
  if (!a) return '';
  const parts: string[] = [];
  if (a.name) parts.push(String(a.name));
  if (a.ip) parts.push(String(a.ip));
  if (a.id !== undefined && a.id !== '') parts.push(`#${a.id}`);
  return parts.join(' · ');
}

function ruleMeta(a: Alert): string {
  const r = a.rule_ref;
  const bits: string[] = [];
  if (r?.id !== undefined && r.id !== '') bits.push(`rule ${r.id}`);
  if (a.location) bits.push(a.location);
  return bits.join(' · ');
}

type Modal =
  | { type: 'assign'; id: string }
  | { type: 'tags'; id: string; current: string[] }
  | { type: 'status'; id: string }
  | { type: 'detail'; alert: Alert }
  | { type: 'bulk-assign'; ids: string[] }
  | { type: 'bulk-tags'; ids: string[] }
  | { type: 'bulk-status'; ids: string[] }
  | { type: 'bulk-escalate'; ids: string[] };

async function runInChunks<T>(items: T[], chunkSize: number, fn: (item: T) => Promise<void>): Promise<void> {
  for (let i = 0; i < items.length; i += chunkSize) {
    const chunk = items.slice(i, i + chunkSize);
    await Promise.all(chunk.map((item) => fn(item)));
  }
}

function sevBadge(sev?: string) {
  const s = (sev || 'medium').toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'new').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'new'}</span>;
}

function relTime(ts?: string): string {
  if (!ts) return '—';
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) return '—';
  const diff = Math.max(0, Date.now() - ms);
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [toast, setToast] = useState('');
  const [modal, setModal] = useState<Modal | null>(null);
  const [modalInput, setModalInput] = useState('');
  const [viewPresets, setViewPresets] = useState<ViewPreset[]>([]);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    try {
      const raw = localStorage.getItem(VIEW_PRESETS_KEY);
      if (raw) {
        const p = JSON.parse(raw) as ViewPreset[];
        if (Array.isArray(p)) setViewPresets(p);
      }
    } catch {
      /* ignore */
    }
  }, []);

  const persistPresets = (p: ViewPreset[]) => {
    setViewPresets(p);
    localStorage.setItem(VIEW_PRESETS_KEY, JSON.stringify(p));
  };

  const saveViewPreset = () => {
    const name = window.prompt('Name for this filter view (e.g. Critical open)');
    if (!name?.trim()) return;
    persistPresets([{ name: name.trim(), filter, sev: sevFilter, status: statusFilter }, ...viewPresets].slice(0, 20));
    notify(`Saved view "${name.trim()}"`);
  };

  const applyPreset = (name: string) => {
    const p = viewPresets.find((x) => x.name === name);
    if (!p) return;
    setFilter(p.filter);
    setSevFilter(p.sev);
    setStatusFilter(p.status);
  };

  const notify = (msg: string) => {
    setToast(msg);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 3000);
  };

  const load = async () => {
    const token = localStorage.getItem('sirp_token') || '';
    const headers: Record<string, string> = {};
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts`, { cache: 'no-store', headers });
    const data = await res.json().catch(() => []);
    setAlerts(Array.isArray(data) ? data : []);
  };

  useEffect(() => { load(); }, []);

  const clearAllAlerts = async () => {
    const t = localStorage.getItem('sirp_token') || '';
    if (!t) {
      notify('Sign in to clear alerts');
      return;
    }
    const n = alerts.length;
    if (!window.confirm(`Hapus SEMUA alert (${n} saat ini di daftar)? Tindakan ini permanen.`)) return;
    if (!window.confirm('Konfirmasi sekali lagi: seluruh alert di database environment ini akan dihapus.')) return;
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${t}` },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = typeof (data as { detail?: string }).detail === 'string' ? (data as { detail: string }).detail : `Gagal (${res.status})`;
      notify(msg);
      return;
    }
    setSelected(new Set());
    const removed = (data as { removed_db?: number }).removed_db;
    notify(typeof removed === 'number' ? `Berhasil menghapus ${removed} alert` : 'Semua alert dihapus');
    load();
  };

  const closeModal = () => { setModal(null); setModalInput(''); };

  const confirmModal = async () => {
    if (!modal) return;
    const token = localStorage.getItem('sirp_token') || '';
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['authorization'] = `Bearer ${token}`;

    if (modal.type === 'assign') {
      if (!modalInput.trim()) {
        notify('Enter assignee');
        return;
      }
      await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${modal.id}/assign`, {
        method: 'POST', headers,
        body: JSON.stringify({ assigned_to: modalInput.trim(), assigned_by: 'ui-admin' }),
      });
      notify(`Assigned alert to ${modalInput.trim()}`);
    } else if (modal.type === 'tags') {
      const tags = modalInput.split(',').map((t) => t.trim()).filter(Boolean);
      await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${modal.id}/tags`, {
        method: 'POST', headers,
        body: JSON.stringify({ tags }),
      });
      notify(`Tags updated`);
    } else if (modal.type === 'status') {
      await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${modal.id}/status`, {
        method: 'POST', headers,
        body: JSON.stringify({ status: modalInput }),
      });
      notify(`Status set to ${modalInput}`);
    } else if (modal.type === 'bulk-assign') {
      if (!modalInput.trim()) {
        notify('Enter assignee');
        return;
      }
      const assignee = modalInput.trim();
      await runInChunks(modal.ids, 5, async (id) => {
        await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/assign`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ assigned_to: assignee, assigned_by: 'bulk-ui' }),
        });
      });
      notify(`Assigned ${modal.ids.length} alerts to ${assignee}`);
      setSelected(new Set());
    } else if (modal.type === 'bulk-tags') {
      const tags = modalInput.split(',').map((t) => t.trim()).filter(Boolean);
      if (!tags.length) {
        notify('Enter at least one tag');
        return;
      }
      await runInChunks(modal.ids, 5, async (id) => {
        await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/tags`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ tags }),
        });
      });
      notify(`Added tags to ${modal.ids.length} alerts`);
      setSelected(new Set());
    } else if (modal.type === 'bulk-status') {
      await runInChunks(modal.ids, 5, async (id) => {
        await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/status`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ status: modalInput }),
        });
      });
      notify(`Updated status on ${modal.ids.length} alerts`);
      setSelected(new Set());
    } else if (modal.type === 'bulk-escalate') {
      let ok = 0;
      let fail = 0;
      await runInChunks(modal.ids, 3, async (id) => {
        const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/escalate`, {
          method: 'POST',
          headers: token ? { authorization: `Bearer ${token}` } : {},
        });
        if (res.ok) ok += 1;
        else fail += 1;
      });
      notify(`Escalated ${ok} alert(s)${fail ? `, ${fail} failed` : ''}`);
      setSelected(new Set());
    }
    closeModal();
    load();
  };

  const escalate = async (id: string) => {
    const token = localStorage.getItem('sirp_token') || '';
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/escalate`, {
      method: 'POST',
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    const data = await res.json().catch(() => ({}));
    if (data.status === 'escalated' && data.case?.id) {
      notify(`Escalated → Case ${data.case.id.slice(0, 8)}…`);
    } else if (data.status === 'already_escalated') {
      const cid = data.case?.id || data.case_id || '';
      notify(cid ? `Already linked to case ${cid.slice(0, 8)}…` : 'Alert was already escalated');
    } else {
      const msg = typeof data.detail === 'string' ? data.detail : (Array.isArray(data.detail) ? JSON.stringify(data.detail) : 'Escalation failed');
      notify(res.ok ? 'Unexpected response' : `${msg} (${res.status})`);
    }
    load();
  };

  const filtered = alerts.filter((a) => {
    if (sevFilter !== 'all' && a.severity?.toLowerCase() !== sevFilter) return false;
    if (statusFilter !== 'all' && a.status?.toLowerCase() !== statusFilter) return false;
    if (filter) {
      const q = filter.toLowerCase();
      const obsHit = (a.observables || []).some(
        (o) =>
          (o.value || '').toLowerCase().includes(q) ||
          (o.type || '').toLowerCase().includes(q),
      );
      return (
        (a.title || '').toLowerCase().includes(q) ||
        (a.source || '').toLowerCase().includes(q) ||
        (a.id || '').toLowerCase().includes(q) ||
        (a.summary || '').toLowerCase().includes(q) ||
        (a.description || '').toLowerCase().includes(q) ||
        agentLine(a.agent).toLowerCase().includes(q) ||
        (a.location || '').toLowerCase().includes(q) ||
        obsHit
      );
    }
    return true;
  });

  const filteredIds = filtered.map((a) => a.id);
  const allFilteredSelected = filteredIds.length > 0 && filteredIds.every((id) => selected.has(id));
  const someFilteredSelected = filteredIds.some((id) => selected.has(id));
  const selectedList = [...selected];

  const toggleRowSelect = (id: string) => {
    setSelected((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };

  const toggleSelectAllFiltered = () => {
    if (allFilteredSelected) {
      setSelected((prev) => {
        const n = new Set(prev);
        filteredIds.forEach((id) => n.delete(id));
        return n;
      });
    } else {
      setSelected((prev) => new Set([...prev, ...filteredIds]));
    }
  };

  return (
    <div>
      {/* Page header */}
      <div className="page-hd">
        <div>
          <h1>Alerts</h1>
          <div className="page-meta">{filtered.length} / {alerts.length} alerts</div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button type="button" onClick={saveViewPreset}>Save view</button>
          <button type="button" className="btn-danger" onClick={() => void clearAllAlerts()}>
            Clear all alerts
          </button>
          <button onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-2" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
        {viewPresets.length > 0 ? (
          <label className="text-muted" style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            Saved views
            <select
              value=""
              onChange={(e) => {
                if (e.target.value) applyPreset(e.target.value);
                e.target.value = '';
              }}
              style={{ fontSize: 12 }}
            >
              <option value="">— load —</option>
              {viewPresets.map((p) => (
                <option key={p.name} value={p.name}>{p.name}</option>
              ))}
            </select>
          </label>
        ) : null}
      </div>
      <div className="flex gap-2 mb-4" style={{ flexWrap: 'wrap' }}>
        <input
          placeholder="Search title, agent, IOC, rule, location…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ minWidth: 220 }}
        />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="all">All statuses</option>
          <option value="new">New</option>
          <option value="triaged">Triaged</option>
          <option value="escalated">Escalated</option>
          <option value="closed">Closed</option>
        </select>
      </div>

      {selectedList.length > 0 ? (
        <div
          className="card mb-3 flex gap-2 flex-wrap items-center"
          style={{ padding: '10px 12px', background: 'var(--bg-elevated)' }}
        >
          <span style={{ fontSize: 13 }}>
            <strong>{selectedList.length}</strong> selected
          </span>
          <button type="button" style={{ fontSize: 12 }} onClick={() => setSelected(new Set())}>
            Clear
          </button>
          <button
            type="button"
            style={{ fontSize: 12 }}
            onClick={() => {
              setModal({ type: 'bulk-assign', ids: selectedList });
              setModalInput('');
            }}
          >
            Assign all…
          </button>
          <button
            type="button"
            style={{ fontSize: 12 }}
            onClick={() => {
              setModal({ type: 'bulk-tags', ids: selectedList });
              setModalInput('');
            }}
          >
            Add tags…
          </button>
          <button
            type="button"
            style={{ fontSize: 12 }}
            onClick={() => {
              setModal({ type: 'bulk-status', ids: selectedList });
              setModalInput('triaged');
            }}
          >
            Set status…
          </button>
          <button
            type="button"
            className="btn-danger"
            style={{ fontSize: 12 }}
            onClick={() => setModal({ type: 'bulk-escalate', ids: selectedList })}
          >
            Escalate all…
          </button>
        </div>
      ) : null}

      {/* Table */}
      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: 36, textAlign: 'center' }}>
              <input
                type="checkbox"
                title="Select all visible"
                checked={allFilteredSelected}
                ref={(el) => {
                  if (el) el.indeterminate = someFilteredSelected && !allFilteredSelected;
                }}
                onChange={toggleSelectAllFiltered}
              />
            </th>
            <th style={{ width: 14 }}></th>
            <th>Title</th>
            <th className="hide-mobile">Endpoint</th>
            <th className="hide-mobile">IOCs</th>
            <th>Risk</th>
            <th>Severity</th>
            <th className="hide-mobile">Source</th>
            <th>Status</th>
            <th className="hide-mobile">Assigned</th>
            <th className="hide-mobile">Age</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((a) => (
            <tr key={a.id}>
              <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                <input
                  type="checkbox"
                  checked={selected.has(a.id)}
                  onChange={() => toggleRowSelect(a.id)}
                  aria-label={`Select alert ${a.id}`}
                />
              </td>
              <td><span className={`indicator ind-${(a.severity || 'medium').toLowerCase()}`}></span></td>
              <td>
                <Link
                  href={`/alerts/${a.id}`}
                  style={{ fontWeight: 500, color: 'var(--accent-blue)' }}
                >
                  {a.title || 'Untitled'}
                </Link>
                <button
                  type="button"
                  onClick={() => setModal({ type: 'detail', alert: a })}
                  className="text-muted"
                  style={{ display: 'block', fontSize: 11, background: 'none', border: 'none', padding: 0, cursor: 'pointer', marginTop: 2 }}
                >
                  Quick preview
                </button>
                {ruleMeta(a) ? <div className="alert-title-sub mono">{ruleMeta(a)}</div> : null}
                {a.tags?.length ? (
                  <div className="tag-list mt-1">
                    {a.tags.slice(0, 4).map((t) => <span className="tag" key={t}>{t}</span>)}
                  </div>
                ) : null}
              </td>
              <td className="text-muted hide-mobile" style={{ fontSize: 12, maxWidth: 160 }} title={agentLine(a.agent)}>
                {agentLine(a.agent) || '—'}
              </td>
              <td className="hide-mobile">
                {(a.observables || []).length ? (
                  <div className="obs-chips" style={{ maxWidth: 200 }}>
                    {a.observables!.slice(0, 3).map((o, i) => (
                      <span className="obs-chip" key={`${o.type}-${i}`} title={o.value}>
                        <span className="obs-chip-type">{o.type || '?'}</span>
                        <span className="truncate" style={{ maxWidth: 100 }}>{o.value}</span>
                      </span>
                    ))}
                    {(a.observables!.length > 3) ? (
                      <span className="text-muted" style={{ fontSize: 11 }}>+{a.observables!.length - 3}</span>
                    ) : null}
                  </div>
                ) : (
                  <span className="text-muted">—</span>
                )}
              </td>
              <td>
                <span className="badge badge-info" title="Queue priority score">{typeof a.risk_score === 'number' ? a.risk_score : '—'}</span>
              </td>
              <td>{sevBadge(a.severity)}</td>
              <td className="text-muted hide-mobile">{a.source || '—'}</td>
              <td>{statusBadge(a.status)}</td>
              <td className="text-muted hide-mobile">{a.assigned_to || '—'}</td>
              <td className="text-muted hide-mobile">{relTime(a.created_at)}</td>
              <td>
                <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                  <button onClick={() => { setModal({ type: 'assign', id: a.id }); setModalInput(a.assigned_to || ''); }}>Assign</button>
                  <button onClick={() => { setModal({ type: 'tags', id: a.id, current: a.tags || [] }); setModalInput((a.tags || []).join(', ')); }}>Tags</button>
                  <button onClick={() => { setModal({ type: 'status', id: a.id }); setModalInput(a.status || 'triaged'); }}>Status</button>
                  <button onClick={() => escalate(a.id)} className="btn-danger">Escalate</button>
                </div>
              </td>
            </tr>
          ))}
          {!filtered.length && (
            <tr><td colSpan={12}><div className="empty-state">No alerts match your filters.</div></td></tr>
          )}
        </tbody>
      </table>

      {/* Modals */}
      {modal && modal.type !== 'detail' && (
        <div className="modal-backdrop" onClick={closeModal}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">
              {modal.type === 'assign' && 'Assign Alert'}
              {modal.type === 'tags' && 'Edit Tags'}
              {modal.type === 'status' && 'Update Status'}
              {modal.type === 'bulk-assign' && `Assign ${modal.ids.length} alerts`}
              {modal.type === 'bulk-tags' && `Add tags to ${modal.ids.length} alerts`}
              {modal.type === 'bulk-status' && `Set status on ${modal.ids.length} alerts`}
              {modal.type === 'bulk-escalate' && `Escalate ${modal.ids.length} alerts to cases`}
            </div>

            {modal.type === 'bulk-escalate' && (
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 0 }}>
                Creates one case per alert (skips duplicates where the API reports already escalated). Runs in small parallel batches.
              </p>
            )}

            {(modal.type === 'assign' || modal.type === 'bulk-assign') && (
              <>
                <label>Assign to (username)</label>
                <input autoFocus value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full" placeholder="analyst@team" />
              </>
            )}

            {(modal.type === 'tags' || modal.type === 'bulk-tags') && (
              <>
                <label>Tags to add (comma separated)</label>
                <input autoFocus value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full" placeholder="triaged, malware, phishing" />
              </>
            )}

            {(modal.type === 'status' || modal.type === 'bulk-status') && (
              <>
                <label>New status</label>
                <select value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full">
                  <option value="new">new</option>
                  <option value="triaged">triaged</option>
                  <option value="escalated">escalated</option>
                  <option value="closed">closed</option>
                </select>
              </>
            )}

            <div className="modal-footer">
              <button onClick={closeModal}>Cancel</button>
              <button className="btn-primary" onClick={confirmModal}>Confirm</button>
            </div>
          </div>
        </div>
      )}

      {modal && modal.type === 'detail' && (
        <div className="modal-backdrop" onClick={closeModal}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">{modal.alert.title || 'Untitled Alert'}</div>

            <div className="alert-detail-section">
              <h4>Case-style summary</h4>
              <dl className="alert-detail-kv">
                <dt>Alert ID</dt>
                <dd className="mono" style={{ fontSize: 12 }}>{modal.alert.id}</dd>
                <dt>Severity</dt>
                <dd>{sevBadge(modal.alert.severity)}</dd>
                <dt>Status</dt>
                <dd>{statusBadge(modal.alert.status)}</dd>
                <dt>Source</dt>
                <dd>{modal.alert.source || '—'}</dd>
                <dt>Assigned</dt>
                <dd>{modal.alert.assigned_to || '—'}</dd>
                <dt>Ingested</dt>
                <dd className="mono" style={{ fontSize: 12 }}>{modal.alert.created_at || '—'}</dd>
                <dt>Risk score</dt>
                <dd><span className="badge badge-info">{typeof modal.alert.risk_score === 'number' ? modal.alert.risk_score : '—'}</span></dd>
              </dl>
            </div>

            <div className="alert-detail-section">
              <h4>Endpoint (agent)</h4>
              <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>
                {agentLine(modal.alert.agent) || '—'}
                {modal.alert.location ? (
                  <span className="text-muted" style={{ display: 'block', marginTop: 4, fontSize: 12 }}>
                    Log location: {modal.alert.location}
                  </span>
                ) : null}
              </p>
            </div>

            <div className="alert-detail-section">
              <h4>Rule / detection</h4>
              <dl className="alert-detail-kv">
                <dt>Rule ID</dt>
                <dd>{modal.alert.rule_ref?.id ?? '—'}</dd>
                <dt>Level</dt>
                <dd>{modal.alert.rule_ref?.level ?? '—'}</dd>
                <dt>Groups</dt>
                <dd>
                  {Array.isArray(modal.alert.rule_ref?.groups)
                    ? (modal.alert.rule_ref!.groups as string[]).join(', ')
                    : (modal.alert.rule_ref?.groups as string) || '—'}
                </dd>
              </dl>
            </div>

            <div className="alert-detail-section">
              <h4>Description</h4>
              <div className="alert-summary">
                {(modal.alert.summary || modal.alert.description || '—').trim()}
              </div>
            </div>

            <div className="alert-detail-section">
              <h4>Observables (auto-extracted IOCs)</h4>
              {(modal.alert.observables || []).length ? (
                <div className="obs-chips">
                  {(modal.alert.observables || []).map((o, i) => (
                    <span className="obs-chip" key={`${o.type}-${i}-${o.value}`} title={o.value}>
                      <span className="obs-chip-type">{o.type || 'other'}</span>
                      <span style={{ wordBreak: 'break-all' }}>{o.value}</span>
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-muted" style={{ fontSize: 13 }}>No IOCs extracted yet.</span>
              )}
            </div>

            <div className="alert-detail-section">
              <h4>Tags</h4>
              <div className="tag-list">
                {(modal.alert.tags || []).map((t) => (
                  <span className="tag" key={t}>{t}</span>
                ))}
                {!(modal.alert.tags || []).length ? <span className="text-muted">—</span> : null}
              </div>
            </div>

            <details style={{ marginTop: 8 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--text-muted)' }}>Raw JSON (full payload)</summary>
              <pre
                className="mono"
                style={{
                  marginTop: 8,
                  fontSize: 11,
                  maxHeight: 240,
                  overflow: 'auto',
                  padding: 10,
                  background: 'var(--bg-base)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {(() => {
                  try {
                    const raw = JSON.stringify(modal.alert.raw ?? modal.alert, null, 2);
                    return raw.length > 12000 ? `${raw.slice(0, 12000)}\n… (truncated)` : raw;
                  } catch {
                    return String(modal.alert.raw);
                  }
                })()}
              </pre>
            </details>

            <div className="modal-footer">
              <button onClick={closeModal}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && <div className="toast success">{toast}</div>}
    </div>
  );
}
