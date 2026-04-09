'use client';

import { useEffect, useRef, useState } from 'react';

const BASE = process.env.NEXT_PUBLIC_API_GATEWAY_URL || 'http://localhost:8000';

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

type AnalyzerResult = {
  value?: string;
  type?: string;
  result?: { risk?: { verdict?: string; final_score?: number } };
};

function sevBadge(sev?: string) {
  const s = (sev || 'medium').toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'open').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'open'}</span>;
}

function verdictBadge(v?: string) {
  if (!v) return <span className="text-muted">—</span>;
  const map: Record<string, string> = { malicious: 'critical', suspicious: 'high', benign: 'low' };
  return <span className={`badge badge-${map[v.toLowerCase()] || 'info'}`}>{v}</span>;
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

export default function CaseDetail({ params }: { params: { id: string } }) {
  const [c, setC] = useState<Case | null>(null);
  const [results, setResults] = useState<AnalyzerResult[]>([]);
  const [toast, setToast] = useState('');
  const [commentText, setCommentText] = useState('');
  const [taskTitle, setTaskTitle] = useState('');
  const [taskAssignee, setTaskAssignee] = useState('');
  const [tab, setTab] = useState<'overview' | 'tasks' | 'comments' | 'timeline' | 'observables' | 'forensics'>('overview');
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

  const token = typeof window !== 'undefined' ? (localStorage.getItem('sirp_token') || '') : '';
  const authHdr = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  const notify = (msg: string) => {
    setToast(msg);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 3000);
  };

  const load = async () => {
    const res = await fetch(`${BASE}/cases/cases/${params.id}`, { cache: 'no-store' });
    if (!res.ok) return;
    const data = await res.json();
    setC(data);
    if (data.alert_id) {
      const r = await fetch(`${BASE}/analyzers/results?alert_id=${encodeURIComponent(data.alert_id)}`, { cache: 'no-store' });
      if (r.ok) setResults(await r.json());
    }
  };

  useEffect(() => { load(); }, [params.id]);

  const setStatus = async (status: string) => {
    const actor = token ? 'admin' : 'ui';
    await fetch(`${BASE}/cases/cases/${params.id}/status`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ status, actor }),
    });
    notify(`Status → ${status}`);
    load();
  };

  const addComment = async () => {
    if (!commentText.trim()) return;
    const author = token ? 'analyst' : 'anonymous';
    await fetch(`${BASE}/cases/cases/${params.id}/comments`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ author, text: commentText }),
    });
    setCommentText('');
    notify('Comment added');
    load();
  };

  const deleteComment = async (cid: string) => {
    await fetch(`${BASE}/cases/cases/${params.id}/comments/${cid}`, { method: 'DELETE', headers: authHdr });
    notify('Comment deleted');
    load();
  };

  const addTask = async () => {
    if (!taskTitle.trim()) return;
    await fetch(`${BASE}/cases/cases/${params.id}/tasks`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ title: taskTitle, assigned_to: taskAssignee }),
    });
    setTaskTitle(''); setTaskAssignee('');
    notify('Task added');
    load();
  };

  const updateTaskStatus = async (tid: string, status: string) => {
    await fetch(`${BASE}/cases/cases/${params.id}/tasks/${tid}`, {
      method: 'PUT', headers: authHdr,
      body: JSON.stringify({ status }),
    });
    notify(`Task → ${status}`);
    load();
  };

  const deleteTask = async (tid: string) => {
    await fetch(`${BASE}/cases/cases/${params.id}/tasks/${tid}`, { method: 'DELETE', headers: authHdr });
    notify('Task deleted');
    load();
  };

  const tabStyle = (t: typeof tab): React.CSSProperties => ({
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
        {(['overview', 'tasks', 'comments', 'timeline', 'observables', 'forensics'] as const).map((t) => (
          <button key={t} style={tabStyle(t)} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'tasks' && c.tasks?.length ? ` (${c.tasks.length})` : ''}
            {t === 'comments' && c.comments?.length ? ` (${c.comments.length})` : ''}
            {t === 'forensics' && results.length ? ` (${results.length})` : ''}
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
        <table className="data-table">
          <thead><tr><th>Type</th><th>Value</th></tr></thead>
          <tbody>
            {(c.observables || []).map((o, i) => (
              <tr key={i}>
                <td><span className="badge badge-info">{o.type}</span></td>
                <td className="mono">{o.value}</td>
              </tr>
            ))}
            {!c.observables?.length && <tr><td colSpan={2}><div className="empty-state">No observables.</div></td></tr>}
          </tbody>
        </table>
      )}

      {/* Forensics */}
      {tab === 'forensics' && (
        <table className="data-table">
          <thead>
            <tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Score</th></tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={i}>
                <td className="mono truncate" style={{ maxWidth: 220 }}>{r.value || '—'}</td>
                <td><span className="badge badge-info">{r.type || '—'}</span></td>
                <td>{verdictBadge(r.result?.risk?.verdict)}</td>
                <td className="mono">{r.result?.risk?.final_score != null ? `${r.result.risk.final_score}/100` : '—'}</td>
              </tr>
            ))}
            {!results.length && <tr><td colSpan={4}><div className="empty-state">No analyzer results.</div></td></tr>}
          </tbody>
        </table>
      )}

      {toast && <div className="toast success">{toast}</div>}
    </div>
  );
}
