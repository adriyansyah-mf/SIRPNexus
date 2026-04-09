'use client';

import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useEffect, useRef, useState } from 'react';

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
  | { type: 'detail'; alert: Alert };

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
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

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

  const closeModal = () => { setModal(null); setModalInput(''); };

  const confirmModal = async () => {
    if (!modal) return;
    const token = localStorage.getItem('sirp_token') || '';
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['authorization'] = `Bearer ${token}`;

    if (modal.type === 'assign') {
      await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${modal.id}/assign`, {
        method: 'POST', headers,
        body: JSON.stringify({ assigned_to: modalInput, assigned_by: 'ui-admin' }),
      });
      notify(`Assigned alert to ${modalInput}`);
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
    }
    closeModal();
    load();
  };

  const runAnalyzers = async (id: string) => {
    const token = localStorage.getItem('sirp_token') || '';
    await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/run-analyzers`, {
      method: 'POST',
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    notify('Analyzer jobs queued');
  };

  const escalate = async (id: string) => {
    const token = localStorage.getItem('sirp_token') || '';
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${id}/escalate`, {
      method: 'POST',
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    const data = await res.json().catch(() => ({}));
    notify(data.status === 'escalated' ? `Escalated → Case ${data.case?.id?.slice(0, 8)}…` : 'Escalation failed');
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

  return (
    <div>
      {/* Page header */}
      <div className="page-hd">
        <div>
          <h1>Alerts</h1>
          <div className="page-meta">{filtered.length} / {alerts.length} alerts</div>
        </div>
        <div className="flex gap-2">
          <button onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Filters */}
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

      {/* Table */}
      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: 14 }}></th>
            <th>Title</th>
            <th className="hide-mobile">Endpoint</th>
            <th className="hide-mobile">IOCs</th>
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
              <td><span className={`indicator ind-${(a.severity || 'medium').toLowerCase()}`}></span></td>
              <td>
                <button
                  onClick={() => setModal({ type: 'detail', alert: a })}
                  style={{ background: 'none', border: 'none', padding: 0, color: 'var(--accent-blue)', textAlign: 'left', cursor: 'pointer', fontWeight: 500 }}
                >
                  {a.title || 'Untitled'}
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
                  <button onClick={() => runAnalyzers(a.id)}>Analyze</button>
                  <button onClick={() => escalate(a.id)} className="btn-danger">Escalate</button>
                </div>
              </td>
            </tr>
          ))}
          {!filtered.length && (
            <tr><td colSpan={10}><div className="empty-state">No alerts match your filters.</div></td></tr>
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
            </div>

            {modal.type === 'assign' && (
              <>
                <label>Assign to (username)</label>
                <input autoFocus value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full" placeholder="analyst@team" />
              </>
            )}

            {modal.type === 'tags' && (
              <>
                <label>Tags (comma separated)</label>
                <input autoFocus value={modalInput} onChange={(e) => setModalInput(e.target.value)} className="w-full" placeholder="triaged, malware, phishing" />
              </>
            )}

            {modal.type === 'status' && (
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
