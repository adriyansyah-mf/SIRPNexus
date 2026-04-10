'use client';

import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';

type RelatedCase = { id: string; title?: string; score?: number; reasons?: string[]; created_at?: string };
type RelatedAlert = { id: string; title?: string; overlap?: number; created_at?: string; source?: string };
type TlEvent = { at?: string; kind?: string; label?: string; detail?: Record<string, unknown> };

function jwtUser(token: string): string {
  try {
    const p = token.split('.')[1];
    const o = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/'))) as { preferred_username?: string; sub?: string };
    return o.preferred_username || o.sub || 'user';
  } catch {
    return 'user';
  }
}

export default function CaseInvestigation({
  caseId,
  alertId,
  onRefreshCase,
}: {
  caseId: string;
  alertId?: string | null;
  onRefreshCase: () => void;
}) {
  const token = typeof window !== 'undefined' ? (localStorage.getItem('sirp_token') || '') : '';
  const auth = token ? { authorization: `Bearer ${token}` } : {};

  const [relatedCases, setRelatedCases] = useState<RelatedCase[]>([]);
  const [relatedAlerts, setRelatedAlerts] = useState<RelatedAlert[]>([]);
  const [timeline, setTimeline] = useState<TlEvent[]>([]);
  const [err, setErr] = useState('');
  const [linking, setLinking] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr('');
    try {
      const [rc, tl] = await Promise.all([
        fetch(`${CLIENT_API_PREFIX}/cases/cases/${caseId}/related?window_days=14&limit=20`, { headers: auth }),
        fetch(`${CLIENT_API_PREFIX}/cases/cases/${caseId}/investigation-timeline`, { headers: auth }),
      ]);
      if (!rc.ok) {
        setErr(`Related: ${rc.status}`);
        return;
      }
      const rj = (await rc.json()) as { related_cases?: RelatedCase[] };
      setRelatedCases(rj.related_cases || []);
      if (tl.ok) {
        const tj = (await tl.json()) as { events?: TlEvent[] };
        setTimeline(tj.events || []);
      }
      if (alertId) {
        const ra = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${alertId}/related?limit=20`, { headers: auth });
        if (ra.ok) {
          const aj = (await ra.json()) as { alerts?: RelatedAlert[] };
          setRelatedAlerts(aj.alerts || []);
        } else {
          setRelatedAlerts([]);
        }
      } else {
        setRelatedAlerts([]);
      }
    } catch {
      setErr('Failed to load investigation data');
    }
  }, [caseId, alertId, auth.authorization]);

  useEffect(() => {
    void load();
  }, [load]);

  const linkTo = async (targetId: string) => {
    if (!token) return;
    setLinking(targetId);
    try {
      const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${caseId}/link`, {
        method: 'POST',
        headers: { ...auth, 'content-type': 'application/json' },
        body: JSON.stringify({ target_case_id: targetId, actor: jwtUser(token) }),
      });
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as { detail?: string };
        setErr(typeof d.detail === 'string' ? d.detail : `Link failed ${res.status}`);
        return;
      }
      onRefreshCase();
      void load();
    } finally {
      setLinking(null);
    }
  };

  return (
    <div>
      {err && (
        <div className="card mb-3" style={{ padding: 12, borderColor: 'var(--sev-high)', fontSize: 13 }}>{err}</div>
      )}

      <div className="card mb-4">
        <div className="card-title mb-2">Related cases</div>
        <p className="text-muted mb-3" style={{ fontSize: 12 }}>
          Same IOCs (weighted) or shared tags; only cases created within the last 14 days (adjust via API).
        </p>
        {!relatedCases.length && <div className="empty-state">No correlated cases found.</div>}
        <table className="data-table">
          <tbody>
            {relatedCases.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link href={`/cases/${r.id}`} style={{ fontWeight: 500 }}>{r.title || r.id}</Link>
                  <div className="text-muted" style={{ fontSize: 11 }}>{(r.reasons || []).join(' · ')}</div>
                </td>
                <td style={{ width: 100 }}><span className="badge badge-info">score {r.score}</span></td>
                <td style={{ width: 120 }}>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ fontSize: 11, padding: '4px 8px' }}
                    disabled={!token || linking === r.id}
                    onClick={() => void linkTo(r.id)}
                  >
                    {linking === r.id ? '…' : 'Link'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {alertId ? (
        <div className="card mb-4">
          <div className="card-title mb-2">Related alerts (shared IOCs)</div>
          <p className="text-muted mb-3" style={{ fontSize: 12 }}>From source alert <span className="mono">{alertId.slice(0, 12)}…</span></p>
          {!relatedAlerts.length && <div className="empty-state">No other alerts with overlapping observables.</div>}
          <ul className="search-hit-list">
            {relatedAlerts.map((a) => (
              <li key={a.id}>
                <span className="mono" style={{ fontSize: 11 }}>{a.id.slice(0, 14)}…</span>
                {' — '}
                {a.title || 'Alert'}
                <span className="text-muted" style={{ fontSize: 11, marginLeft: 8 }}>overlap {a.overlap} · {a.source || '—'}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="card">
        <div className="card-title mb-2">Investigation timeline (merged)</div>
        <p className="text-muted mb-3" style={{ fontSize: 12 }}>
          Timeline events, comments, tasks, evidence uploads, and source alert — chronological.
        </p>
        {!timeline.length && <div className="empty-state">No events.</div>}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {timeline.map((e, i) => (
            <div
              key={`${e.at}-${i}`}
              style={{
                borderLeft: '3px solid var(--accent-blue)',
                paddingLeft: 12,
                fontSize: 13,
              }}
            >
              <div className="text-muted" style={{ fontSize: 11 }}>{e.at || '—'} · {e.kind || 'event'}</div>
              <div>{e.label || '—'}</div>
              {e.detail && Object.keys(e.detail).length > 0 ? (
                <pre className="mono text-muted" style={{ fontSize: 10, marginTop: 4, whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(e.detail, null, 0).slice(0, 400)}
                </pre>
              ) : null}
            </div>
          ))}
        </div>
      </div>

      <button type="button" className="mt-3" onClick={() => void load()} style={{ fontSize: 12 }}>
        ↻ Refresh investigation
      </button>
    </div>
  );
}
