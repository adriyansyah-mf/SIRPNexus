'use client';

import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useEffect, useRef, useState } from 'react';

type Alert = {
  id: string;
  severity?: string;
  source?: string;
  status?: string;
  title?: string;
  description?: string;
  tags?: string[];
  assigned_to?: string;
  created_at?: string;
};

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
      return (
        (a.title || '').toLowerCase().includes(q) ||
        (a.source || '').toLowerCase().includes(q) ||
        (a.id || '').toLowerCase().includes(q)
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
          placeholder="Search title, source, ID…"
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
                {a.tags?.length ? (
                  <div className="tag-list mt-1">
                    {a.tags.slice(0, 3).map((t) => <span className="tag" key={t}>{t}</span>)}
                  </div>
                ) : null}
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
            <tr><td colSpan={8}><div className="empty-state">No alerts match your filters.</div></td></tr>
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
          <div className="modal" style={{ maxWidth: 600, width: '92vw' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">{modal.alert.title || 'Untitled Alert'}</div>
            <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
              <tbody>
                {[
                  ['ID', <span className="mono">{modal.alert.id}</span>],
                  ['Severity', sevBadge(modal.alert.severity)],
                  ['Status', statusBadge(modal.alert.status)],
                  ['Source', modal.alert.source || '—'],
                  ['Assigned to', modal.alert.assigned_to || '—'],
                  ['Ingested', modal.alert.created_at || '—'],
                  ['Tags', (modal.alert.tags || []).join(', ') || '—'],
                  ['Description', modal.alert.description || '—'],
                ].map(([k, v]) => (
                  <tr key={String(k)}>
                    <td style={{ color: 'var(--text-muted)', padding: '5px 0', width: 120, verticalAlign: 'top' }}>{k}</td>
                    <td style={{ padding: '5px 0' }}>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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
