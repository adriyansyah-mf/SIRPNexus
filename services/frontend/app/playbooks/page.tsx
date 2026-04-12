'use client';

import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useEffect, useRef, useState } from 'react';

type Playbook = {
  id: string;
  name: string;
  description?: string;
  trigger: string;
  conditions: { field: string; op: string; value: string | number }[];
  actions: { type: string; params?: Record<string, string> }[];
  enabled: boolean;
  created_at?: string;
};

type Run = {
  id: string;
  playbook_id: string;
  trigger: string;
  action_results: { type: string; ok: boolean; at: string }[];
  ran_at: string;
};

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

const ACTION_TYPES = ['firewall_block', 'wazuh_active_response', 'edr_isolate', 'webhook_notify'];
const TRIGGER_TYPES = ['case_event', 'manual'];

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [tab, setTab] = useState<'playbooks' | 'runs'>('playbooks');
  const [showCreate, setShowCreate] = useState(false);
  const [toast, setToast] = useState('');
  const toastRef = useRef<ReturnType<typeof setTimeout>>();
  const [form, setForm] = useState({
    name: '', description: '', trigger: 'case_event', enabled: true,
    conditions: [{ field: 'event', op: 'eq', value: 'created' }],
    actions: [{ type: 'firewall_block', params: { target_field: 'value' } }],
  });

  const postJson: RequestInit = { credentials: 'include', headers: { 'content-type': 'application/json' } };

  const notify = (msg: string) => {
    setToast(msg);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 3500);
  };

  const load = async () => {
    const [pbRes, runsRes] = await Promise.all([
      fetch(`${CLIENT_API_PREFIX}/automation/automation/playbooks`, { cache: 'no-store', credentials: 'include' }),
      fetch(`${CLIENT_API_PREFIX}/automation/automation/runs?limit=50`, { cache: 'no-store', credentials: 'include' }),
    ]);
    if (pbRes.ok) setPlaybooks(await pbRes.json());
    if (runsRes.ok) setRuns(await runsRes.json());
  };

  useEffect(() => { load(); }, []);

  const toggle = async (pb: Playbook) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/automation/automation/playbooks/${pb.id}/toggle`, {
      method: 'PUT',
      ...postJson,
      body: JSON.stringify({ enabled: !pb.enabled }),
    });
    if (res.ok) { notify(`${pb.name} ${!pb.enabled ? 'enabled' : 'disabled'}`); load(); }
    else notify('Failed to toggle (built-in playbooks cannot be toggled via API)', );
  };

  const deletePlaybook = async (id: string) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/automation/automation/playbooks/${id}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    if (res.ok) { notify('Playbook deleted'); load(); }
    else notify('Cannot delete built-in playbook');
  };

  const runManual = async (id: string) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/automation/automation/playbooks/${id}/run`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({ ioc_type: 'ip', value: '1.2.3.4', risk: { final_score: 90 } }),
    });
    const data = await res.json();
    notify(res.ok ? `Ran ${id}: ${data.actions?.length || 0} actions` : 'Run failed');
    load();
  };

  const createPlaybook = async () => {
    if (!form.name) { notify('Name required'); return; }
    const res = await fetch(`${CLIENT_API_PREFIX}/automation/automation/playbooks`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify(form),
    });
    const data = await res.json();
    if (res.ok) { notify(`Created ${data.id}`); setShowCreate(false); load(); }
    else notify(data.detail || 'Create failed');
  };

  const tabStyle = (t: typeof tab): React.CSSProperties => ({
    padding: '8px 14px', fontSize: 13, cursor: 'pointer', background: 'none', border: 'none', borderRadius: 0,
    fontWeight: tab === t ? 600 : 400,
    color: tab === t ? 'var(--text-primary)' : 'var(--text-secondary)',
    borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
  });

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Playbooks</h1>
          <div className="page-meta">{playbooks.filter(p => p.enabled).length} active · {playbooks.length} total</div>
        </div>
        <div className="flex gap-2">
          <button onClick={load}>↻ Refresh</button>
          <button className="btn-primary" onClick={() => setShowCreate(true)}>+ New Playbook</button>
        </div>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', marginBottom: 16 }}>
        <button style={tabStyle('playbooks')} onClick={() => setTab('playbooks')}>Playbooks ({playbooks.length})</button>
        <button style={tabStyle('runs')} onClick={() => setTab('runs')}>Run History ({runs.length})</button>
      </div>

      {tab === 'playbooks' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Trigger</th>
              <th>Conditions</th>
              <th>Actions</th>
              <th>Status</th>
              <th>Operations</th>
            </tr>
          </thead>
          <tbody>
            {playbooks.map((pb) => (
              <tr key={pb.id}>
                <td>
                  <div style={{ fontWeight: 500 }}>{pb.name}</div>
                  <div className="text-muted" style={{ fontSize: 11 }}>{pb.description}</div>
                </td>
                <td><span className="badge badge-info">{pb.trigger}</span></td>
                <td className="text-muted" style={{ fontSize: 11 }}>
                  {(pb.conditions || []).map((c, i) => <div key={i}>{c.field} {c.op} {String(c.value)}</div>)}
                </td>
                <td className="text-muted" style={{ fontSize: 11 }}>
                  {(pb.actions || []).map((a, i) => <div key={i}>{a.type}</div>)}
                </td>
                <td>
                  {pb.enabled
                    ? <span className="badge badge-closed">Enabled</span>
                    : <span className="badge badge-new">Disabled</span>}
                </td>
                <td>
                  <div className="flex gap-1">
                    <button onClick={() => runManual(pb.id)}>▶ Run</button>
                    <button onClick={() => toggle(pb)}>{pb.enabled ? 'Disable' : 'Enable'}</button>
                    {!pb.id.startsWith('pb-block') && !pb.id.startsWith('pb-isolate') && !pb.id.startsWith('pb-notify') && (
                      <button className="btn-danger" onClick={() => deletePlaybook(pb.id)}>Delete</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {!playbooks.length && <tr><td colSpan={6}><div className="empty-state">No playbooks.</div></td></tr>}
          </tbody>
        </table>
      )}

      {tab === 'runs' && (
        <table className="data-table">
          <thead>
            <tr><th>Playbook</th><th>Trigger</th><th>Actions</th><th>Success</th><th>Age</th></tr>
          </thead>
          <tbody>
            {runs.map((r) => {
              const ok = r.action_results?.filter(a => a.ok).length || 0;
              const total = r.action_results?.length || 0;
              return (
                <tr key={r.id}>
                  <td className="mono" style={{ fontSize: 11 }}>{r.playbook_id}</td>
                  <td><span className="badge badge-info">{r.trigger}</span></td>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {(r.action_results || []).map((a, i) => <div key={i}>{a.type}: {a.ok ? '✓' : '✗'}</div>)}
                  </td>
                  <td>
                    <span className={`badge ${ok === total ? 'badge-closed' : ok > 0 ? 'badge-triaged' : 'badge-escalated'}`}>
                      {ok}/{total}
                    </span>
                  </td>
                  <td className="text-muted">{relTime(r.ran_at)}</td>
                </tr>
              );
            })}
            {!runs.length && <tr><td colSpan={5}><div className="empty-state">No runs yet.</div></td></tr>}
          </tbody>
        </table>
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="modal-backdrop" onClick={() => setShowCreate(false)}>
          <div className="modal" style={{ maxWidth: 560 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Create Playbook</div>
            <div className="form-row">
              <div>
                <label>Name</label>
                <input value={form.name} onChange={(e) => setForm(p => ({ ...p, name: e.target.value }))} className="w-full" />
              </div>
              <div>
                <label>Description</label>
                <input value={form.description} onChange={(e) => setForm(p => ({ ...p, description: e.target.value }))} className="w-full" />
              </div>
              <div>
                <label>Trigger</label>
                <select value={form.trigger} onChange={(e) => setForm(p => ({ ...p, trigger: e.target.value }))} className="w-full">
                  {TRIGGER_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label>Condition — field</label>
                <input
                  placeholder="e.g. risk.final_score"
                  value={form.conditions[0]?.field || ''}
                  onChange={(e) => setForm(p => ({ ...p, conditions: [{ ...p.conditions[0], field: e.target.value }] }))}
                  className="w-full"
                />
              </div>
              <div className="flex gap-2">
                <div style={{ flex: 1 }}>
                  <label>Op</label>
                  <select
                    value={form.conditions[0]?.op || 'eq'}
                    onChange={(e) => setForm(p => ({ ...p, conditions: [{ ...p.conditions[0], op: e.target.value }] }))}
                    className="w-full"
                  >
                    {['eq', 'neq', 'gte', 'gt', 'contains'].map(o => <option key={o}>{o}</option>)}
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label>Value</label>
                  <input
                    value={String(form.conditions[0]?.value || '')}
                    onChange={(e) => setForm(p => ({ ...p, conditions: [{ ...p.conditions[0], value: e.target.value }] }))}
                    className="w-full"
                  />
                </div>
              </div>
              <div>
                <label>Action Type</label>
                <select
                  value={form.actions[0]?.type || 'firewall_block'}
                  onChange={(e) => setForm(p => ({ ...p, actions: [{ ...p.actions[0], type: e.target.value }] }))}
                  className="w-full"
                >
                  {ACTION_TYPES.map(a => <option key={a}>{a}</option>)}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="btn-primary" onClick={createPlaybook}>Create</button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast success">{toast}</div>}
    </div>
  );
}
