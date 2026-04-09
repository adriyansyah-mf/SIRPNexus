'use client';

import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import { openctiKnowledgeSearchUrl } from '../../../lib/openctiLinks';
import { useEffect, useRef, useState, type CSSProperties } from 'react';

type Case = {
  id: string;
  title?: string;
  description?: string;
  status?: string;
  severity?: string;
  owner?: string;
  assigned_to?: string;
  created_at?: string;
  updated_at?: string;
  alert_id?: string;
  tags?: string[];
  sla?: { response_due: string; resolution_due: string; breached: boolean };
  timeline?: { event: string; at: string }[];
  comments?: { id: string; author: string; text: string; at: string; edited?: boolean }[];
  tasks?: { id: string; title: string; status: string; assigned_to?: string }[];
  observables?: { type: string; value: string }[];
};

type OpenctiMatch = {
  id?: string;
  standard_id?: string;
  entity_type?: string;
  observable_value?: string;
  description?: string;
  confidence?: number;
  created_at?: string;
  updated_at?: string;
};

type OpenctiLookupModal = {
  iocType: string;
  iocValue: string;
  loading: boolean;
  error: string | null;
  result: {
    search: string;
    matches: OpenctiMatch[];
    page_info?: { globalCount?: number };
    graphql_errors?: unknown;
  } | null;
};

function sevBadge(sev?: string) {
  const s = (sev || 'medium').toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'open').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'open'}</span>;
}

function relTime(ts?: string) {
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

const OPENCTI_URL = (process.env.NEXT_PUBLIC_OPENCTI_URL || '').trim();

export default function CaseDetail({ params }: { params: { id: string } }) {
  const [c, setC] = useState<Case | null>(null);
  const [toast, setToast] = useState('');
  const [commentText, setCommentText] = useState('');
  const [taskTitle, setTaskTitle] = useState('');
  const [taskAssignee, setTaskAssignee] = useState('');
  const [tab, setTab] = useState<'overview' | 'tasks' | 'comments' | 'timeline' | 'observables'>('overview');
  const [openctiModal, setOpenctiModal] = useState<OpenctiLookupModal | null>(null);
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

  const token = typeof window !== 'undefined' ? (localStorage.getItem('sirp_token') || '') : '';
  const authHdr = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  const notify = (msg: string) => {
    setToast(msg);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 3000);
  };

  const load = async () => {
    const h = token ? { authorization: `Bearer ${token}` } : {};
    const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}`, { cache: 'no-store', headers: h });
    if (!res.ok) return;
    const data = await res.json();
    setC(data);
  };

  useEffect(() => { load(); }, [params.id]);

  const lookupOpenctiGraphql = async (o: { type: string; value: string }) => {
    setOpenctiModal({
      iocType: o.type,
      iocValue: o.value,
      loading: true,
      error: null,
      result: null,
    });
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/opencti/lookup`, {
      method: 'POST',
      headers: authHdr,
      body: JSON.stringify({ value: o.value, type: o.type, first: 25 }),
    });
    const data = (await res.json().catch(() => ({}))) as {
      detail?: string;
      search?: string;
      matches?: OpenctiMatch[];
      page_info?: { globalCount?: number };
      graphql_errors?: unknown;
    };
    if (!res.ok) {
      const msg = typeof data.detail === 'string' ? data.detail : `OpenCTI lookup failed (${res.status})`;
      setOpenctiModal((m) => (m ? { ...m, loading: false, error: msg } : null));
      return;
    }
    setOpenctiModal((m) =>
      m
        ? {
            ...m,
            loading: false,
            error: null,
            result: {
              search: data.search || o.value,
              matches: Array.isArray(data.matches) ? data.matches : [],
              page_info: data.page_info,
              graphql_errors: data.graphql_errors,
            },
          }
        : null,
    );
  };

  const setStatus = async (status: string) => {
    const actor = token ? 'admin' : 'ui';
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/status`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ status, actor }),
    });
    notify(`Status → ${status}`);
    load();
  };

  const addComment = async () => {
    if (!commentText.trim()) return;
    const author = token ? 'analyst' : 'anonymous';
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/comments`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ author, text: commentText }),
    });
    setCommentText('');
    notify('Comment added');
    load();
  };

  const deleteComment = async (cid: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/comments/${cid}`, { method: 'DELETE', headers: authHdr });
    notify('Comment deleted');
    load();
  };

  const addTask = async () => {
    if (!taskTitle.trim()) return;
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ title: taskTitle, assigned_to: taskAssignee }),
    });
    setTaskTitle(''); setTaskAssignee('');
    notify('Task added');
    load();
  };

  const updateTaskStatus = async (tid: string, status: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks/${tid}`, {
      method: 'PUT', headers: authHdr,
      body: JSON.stringify({ status }),
    });
    notify(`Task → ${status}`);
    load();
  };

  const deleteTask = async (tid: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks/${tid}`, { method: 'DELETE', headers: authHdr });
    notify('Task deleted');
    load();
  };

  const tabStyle = (t: typeof tab): CSSProperties => ({
    padding: '8px 14px', cursor: 'pointer', fontSize: 13, fontWeight: tab === t ? 600 : 400,
    color: tab === t ? 'var(--text-primary)' : 'var(--text-secondary)',
    borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
    background: 'none', border: 'none', borderRadius: 0,
  });

  if (!c) return <div className="empty-state">Loading case…</div>;

  return (
    <div>
      {/* Header */}
      <div className="page-hd">
        <div>
          <h1 style={{ marginBottom: 4 }}>{c.title}</h1>
          <div className="flex gap-2 items-center">
            {sevBadge(c.severity)}{statusBadge(c.status)}
            {c.assigned_to && <span className="text-muted" style={{ fontSize: 12 }}>Assigned: {c.assigned_to}</span>}
            <span className="text-muted" style={{ fontSize: 12 }}>Created {relTime(c.created_at)}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <select
            value={c.status}
            onChange={(e) => setStatus(e.target.value)}
            style={{ fontSize: 12 }}
          >
            <option value="open">open</option>
            <option value="in-progress">in-progress</option>
            <option value="resolved">resolved</option>
            <option value="closed">closed</option>
          </select>
          <button onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', marginBottom: 16 }}>
        {(['overview', 'tasks', 'comments', 'timeline', 'observables'] as const).map((t) => (
          <button key={t} style={tabStyle(t)} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'tasks' && c.tasks?.length ? ` (${c.tasks.length})` : ''}
            {t === 'comments' && c.comments?.length ? ` (${c.comments.length})` : ''}
          </button>
        ))}
      </div>

      {/* Overview */}
      {tab === 'overview' && (
        <div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <tbody>
              {[
                ['Case ID', <span className="mono">{c.id}</span>],
                ['Severity', sevBadge(c.severity)],
                ['Status', statusBadge(c.status)],
                ['Owner', c.owner || '—'],
                ['Assigned to', c.assigned_to || '—'],
                ['Tags', (c.tags || []).map(t => <span key={t} className="tag">{t}</span>) || '—'],
                ['Alert ID', c.alert_id ? <span className="mono">{c.alert_id.slice(0, 24)}…</span> : '—'],
                ['SLA Response due', c.sla?.response_due ? relTime(c.sla.response_due) : '—'],
                ['SLA Resolution due', c.sla?.resolution_due ? relTime(c.sla.resolution_due) : '—'],
                ['Created', c.created_at || '—'],
                ['Last updated', c.updated_at || '—'],
                ['Description', <span style={{ whiteSpace: 'pre-wrap' }}>{c.description || '—'}</span>],
              ].map(([k, v]) => (
                <tr key={String(k)} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '7px 0', width: 150, color: 'var(--text-muted)', verticalAlign: 'top' }}>{k}</td>
                  <td style={{ padding: '7px 0' }}>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tasks */}
      {tab === 'tasks' && (
        <div>
          <div className="card mb-4">
            <div className="card-title mb-2">Add Task</div>
            <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
              <input placeholder="Task title" value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
              <input placeholder="Assign to (optional)" value={taskAssignee} onChange={(e) => setTaskAssignee(e.target.value)} style={{ width: 160 }} />
              <button className="btn-primary" onClick={addTask}>+ Add Task</button>
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr><th>Title</th><th>Assigned</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {(c.tasks || []).map((t) => (
                <tr key={t.id}>
                  <td>{t.title}</td>
                  <td className="text-muted">{t.assigned_to || '—'}</td>
                  <td>
                    <select value={t.status} onChange={(e) => updateTaskStatus(t.id, e.target.value)} style={{ fontSize: 11 }}>
                      <option value="open">open</option>
                      <option value="in-progress">in-progress</option>
                      <option value="done">done</option>
                    </select>
                  </td>
                  <td><button className="btn-danger" onClick={() => deleteTask(t.id)}>Delete</button></td>
                </tr>
              ))}
              {!c.tasks?.length && <tr><td colSpan={4}><div className="empty-state">No tasks yet.</div></td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* Comments */}
      {tab === 'comments' && (
        <div>
          <div className="card mb-4">
            <div className="card-title mb-2">Add Comment</div>
            <textarea
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Write a comment…"
              style={{ width: '100%', minHeight: 80, resize: 'vertical', marginBottom: 8 }}
            />
            <button className="btn-primary" onClick={addComment}>Post Comment</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(c.comments || []).map((cm) => (
              <div key={cm.id} className="card" style={{ padding: '12px 14px' }}>
                <div className="flex items-center gap-2 mb-1">
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{cm.author}</span>
                  <span className="text-muted" style={{ fontSize: 11 }}>{relTime(cm.at)}</span>
                  {cm.edited && <span className="badge badge-info" style={{ fontSize: 9 }}>edited</span>}
                  <button className="btn-danger ml-auto" onClick={() => deleteComment(cm.id)}>Delete</button>
                </div>
                <div style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{cm.text}</div>
              </div>
            ))}
            {!c.comments?.length && <div className="empty-state">No comments yet.</div>}
          </div>
        </div>
      )}

      {/* Timeline */}
      {tab === 'timeline' && (
        <div style={{ borderLeft: '2px solid var(--border-subtle)', paddingLeft: 16 }}>
          {(c.timeline || []).map((e, i) => (
            <div key={i} style={{ marginBottom: 12, position: 'relative' }}>
              <div style={{
                width: 8, height: 8, background: 'var(--accent-blue)', borderRadius: '50%',
                position: 'absolute', left: -20, top: 4,
              }} />
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{relTime(e.at)}</div>
              <div style={{ fontSize: 13 }}>{e.event}</div>
            </div>
          ))}
          {!c.timeline?.length && <div className="empty-state">No timeline events.</div>}
        </div>
      )}

      {/* Observables */}
      {tab === 'observables' && (
        <div>
          <p className="text-muted mb-3" style={{ fontSize: 13 }}>
            <strong>Lookup</strong> calls OpenCTI <code className="mono">POST …/graphql</code> (<code className="mono">stixCyberObservables(search: …)</code>).
            Uses <code className="mono">OPENCTI_URL</code> + <code className="mono">OPENCTI_TOKEN</code> on alert-service (DB secrets or env).
            {OPENCTI_URL ? (
              <> Optional <strong>UI ↗</strong> opens the web app in a new tab.</>
            ) : null}
          </p>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th style={{ minWidth: 200 }}>OpenCTI</th>
              </tr>
            </thead>
            <tbody>
              {(c.observables || []).map((o, i) => {
                const uiHref = openctiKnowledgeSearchUrl(o.value);
                return (
                  <tr key={`${i}:${o.type}:${o.value}`}>
                    <td><span className="badge badge-info">{o.type}</span></td>
                    <td className="mono">{o.value}</td>
                    <td>
                      <div className="flex gap-1" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
                        <button
                          type="button"
                          className="btn-primary"
                          style={{ fontSize: 12, padding: '4px 10px' }}
                          onClick={() => void lookupOpenctiGraphql(o)}
                        >
                          Lookup
                        </button>
                        {uiHref ? (
                          <a
                            href={uiHref}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontSize: 12 }}
                          >
                            UI ↗
                          </a>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!c.observables?.length && <tr><td colSpan={3}><div className="empty-state">No observables.</div></td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {openctiModal && (
        <div className="modal-backdrop" onClick={() => setOpenctiModal(null)}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">
              OpenCTI GraphQL · <span className="mono" style={{ fontWeight: 400 }}>{openctiModal.iocValue}</span>
              <span className="badge badge-info ml-2" style={{ fontSize: 10 }}>{openctiModal.iocType}</span>
            </div>
            {openctiModal.loading && <div className="empty-state">Querying OpenCTI…</div>}
            {openctiModal.error && (
              <div className="card" style={{ padding: 12, borderColor: 'var(--sev-high)' }}>
                <div style={{ fontSize: 13, color: 'var(--sev-high)' }}>{openctiModal.error}</div>
              </div>
            )}
            {!openctiModal.loading && openctiModal.result && (
              <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
                {openctiModal.result.graphql_errors ? (
                  <pre className="mono" style={{ fontSize: 11, color: 'var(--sev-high)', marginBottom: 12 }}>
                    {JSON.stringify(openctiModal.result.graphql_errors, null, 2)}
                  </pre>
                ) : null}
                {openctiModal.result.page_info?.globalCount != null && (
                  <div className="text-muted mb-2" style={{ fontSize: 12 }}>
                    Global count (platform): {openctiModal.result.page_info.globalCount}
                  </div>
                )}
                {!openctiModal.result.matches.length && !openctiModal.result.graphql_errors ? (
                  <div className="empty-state">No matching cyber observables in OpenCTI for this search.</div>
                ) : null}
                {openctiModal.result.matches.length > 0 && (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Confidence</th>
                        <th className="hide-mobile">ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {openctiModal.result.matches.map((m, j) => (
                        <tr key={m.id || j}>
                          <td><span className="badge badge-info">{m.entity_type || '—'}</span></td>
                          <td className="mono" style={{ maxWidth: 240 }}>{m.observable_value || '—'}</td>
                          <td>{m.confidence != null ? String(m.confidence) : '—'}</td>
                          <td className="mono hide-mobile" style={{ fontSize: 10 }}>{m.id || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {openctiModal.result.matches.some((m) => m.description) ? (
                  <div style={{ marginTop: 12 }}>
                    {openctiModal.result.matches.map((m, j) =>
                      m.description ? (
                        <div key={`d-${m.id || j}`} className="text-muted" style={{ fontSize: 12, marginBottom: 8 }}>
                          <strong>{m.observable_value}</strong>: {m.description}
                        </div>
                      ) : null,
                    )}
                  </div>
                ) : null}
              </div>
            )}
            <div className="modal-footer">
              <button type="button" onClick={() => setOpenctiModal(null)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast success">{toast}</div>}
    </div>
  );
}
