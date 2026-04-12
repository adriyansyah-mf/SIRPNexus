'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import { useEffect, useState } from 'react';

type AgentBlock = { id?: string; name?: string; ip?: string };
type RuleRef = { id?: string | number; level?: number; groups?: string[] | string; description?: string };
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

function sevBadge(sev?: string) {
  const s = (sev || 'medium').toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'new').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'new'}</span>;
}

export default function AlertDetailPage({ params }: { params: { id: string } }) {
  const [alert, setAlert] = useState<Alert | null>(null);
  const [err, setErr] = useState('');
  const [toast, setToast] = useState('');

  const load = async () => {
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${params.id}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setErr(res.status === 404 ? 'Alert not found.' : `Failed to load (${res.status})`);
      setAlert(null);
      return;
    }
    setErr('');
    setAlert((await res.json()) as Alert);
  };

  useEffect(() => {
    void load();
  }, [params.id]);

  const escalate = async () => {
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${params.id}/escalate`, {
      method: 'POST',
      credentials: 'include',
    });
    const data = (await res.json().catch(() => ({}))) as {
      status?: string;
      case?: { id?: string };
      detail?: string;
    };
    if (data.status === 'escalated' && data.case?.id) {
      setToast(`Case created: ${data.case.id}`);
      setTimeout(() => setToast(''), 4000);
    } else if (data.status === 'already_escalated' && data.case?.id) {
      setToast(`Already escalated → ${data.case.id}`);
    } else {
      setToast(typeof data.detail === 'string' ? data.detail : 'Escalation failed');
    }
  };

  if (err) {
    return (
      <div>
        <div className="page-hd"><h1>Alert</h1></div>
        <p style={{ color: 'var(--sev-high)' }}>{err}</p>
        <Link href="/alerts">← Back to alerts</Link>
      </div>
    );
  }

  if (!alert) return <div className="empty-state">Loading alert…</div>;

  const rs = typeof alert.risk_score === 'number' ? alert.risk_score : 0;

  return (
    <div>
      <div className="page-hd">
        <div>
          <div className="flex gap-2 items-center mb-1" style={{ flexWrap: 'wrap' }}>
            <Link href="/alerts" style={{ fontSize: 13 }}>← Alerts</Link>
          </div>
          <h1 style={{ marginBottom: 6 }}>{alert.title || 'Untitled alert'}</h1>
          <div className="flex gap-2 flex-wrap items-center">
            {sevBadge(alert.severity)}
            {statusBadge(alert.status)}
            <span className="badge badge-info" title="SOC queue priority (heuristic)">risk {rs}</span>
            {alert.source ? <span className="text-muted" style={{ fontSize: 12 }}>{alert.source}</span> : null}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button type="button" className="btn-primary" onClick={() => void escalate()}>Escalate to case</button>
          <Link href={`/search?q=${encodeURIComponent(alert.id)}`} style={{ fontSize: 13 }}>Search references</Link>
          <button type="button" onClick={() => void load()}>↻ Refresh</button>
        </div>
      </div>

      {toast ? <div className="toast success" style={{ marginBottom: 12 }}>{toast}</div> : null}

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Identifiers</div>
        <dl className="alert-detail-kv">
          <dt>Alert ID</dt>
          <dd className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{alert.id}</dd>
          <dt>Assigned</dt>
          <dd>{alert.assigned_to || '—'}</dd>
          <dt>Ingested</dt>
          <dd className="mono" style={{ fontSize: 12 }}>{alert.created_at || '—'}</dd>
        </dl>
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Endpoint</div>
        <p style={{ margin: 0, fontSize: 13 }}>{agentLine(alert.agent) || '—'}</p>
        {alert.location ? <p className="text-muted" style={{ fontSize: 12, marginTop: 6 }}>Location: {alert.location}</p> : null}
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Rule / detection</div>
        <dl className="alert-detail-kv">
          <dt>Rule ID</dt>
          <dd>{alert.rule_ref?.id ?? '—'}</dd>
          <dt>Level</dt>
          <dd>{alert.rule_ref?.level ?? '—'}</dd>
        </dl>
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Summary</div>
        <div style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{(alert.summary || alert.description || '—').trim()}</div>
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Observables</div>
        {(alert.observables || []).length ? (
          <div className="obs-chips">
            {(alert.observables || []).map((o, i) => (
              <span className="obs-chip" key={`${o.type}-${i}`}>
                <span className="obs-chip-type">{o.type || '?'}</span>
                <span style={{ wordBreak: 'break-all' }}>{o.value}</span>
              </span>
            ))}
          </div>
        ) : (
          <span className="text-muted">No IOCs.</span>
        )}
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Tags</div>
        <div className="tag-list">
          {(alert.tags || []).map((t) => <span className="tag" key={t}>{t}</span>)}
          {!(alert.tags || []).length ? <span className="text-muted">—</span> : null}
        </div>
      </div>

      <details className="card" style={{ padding: 14 }}>
        <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Raw JSON</summary>
        <pre className="mono" style={{ fontSize: 11, marginTop: 12, maxHeight: 400, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
          {JSON.stringify(alert.raw ?? alert, null, 2).slice(0, 20000)}
        </pre>
      </details>
    </div>
  );
}
