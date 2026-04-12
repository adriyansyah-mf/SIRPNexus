'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useCallback, useEffect, useState } from 'react';
import LiveFeed from './LiveFeed';

type AlertItem = {
  id: string;
  severity?: string;
  source?: string;
  status?: string;
  title?: string;
  assigned_to?: string;
  created_at?: string;
};

type CaseItem = {
  id: string;
  title: string;
  status?: string;
  created_at?: string;
};

type SocSummary = {
  generated_at?: string;
  alerts?: { total?: number; open?: number; critical?: number; avg_risk_score?: number; by_source?: Record<string, number> };
  cases?: {
    total?: number;
    open?: number;
    legal_hold?: number;
    mttr_resolved_hours?: number | null;
    incident_categories?: Record<string, number>;
  };
};

type OpsHealth = {
  generated_at?: string;
  gateway_database?: { ok?: boolean };
  services?: { service?: string; ok?: boolean }[];
};

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

async function fetchJson<T>(path: string): Promise<T> {
  try {
    const res = await fetch(`${CLIENT_API_PREFIX}${path}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) return [] as T;
    return (await res.json()) as T;
  } catch {
    return [] as T;
  }
}

export default function DashboardClient() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [soc, setSoc] = useState<SocSummary | null>(null);
  const [ops, setOps] = useState<OpsHealth | null>(null);
  const load = useCallback(async () => {
    const [a, c, s, o] = await Promise.all([
      fetchJson<AlertItem[]>('/alerts/alerts'),
      fetchJson<CaseItem[]>('/cases/cases'),
      fetch(`${CLIENT_API_PREFIX}/soc/summary`, { cache: 'no-store', credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(`${CLIENT_API_PREFIX}/soc/ops-status`, { cache: 'no-store', credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]);
    setAlerts(Array.isArray(a) ? a : []);
    setCases(Array.isArray(c) ? c : []);
    setSoc(s && typeof s === 'object' ? (s as SocSummary) : null);
    setOps(o && typeof o === 'object' ? (o as OpsHealth) : null);
  }, []);

  useEffect(() => {
    load();
    const onVis = () => {
      if (document.visibilityState === 'visible') load();
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, [load]);

  const critical = alerts.filter((a) => a.severity?.toLowerCase() === 'critical').length;
  const open = alerts.filter((a) => a.status?.toLowerCase() !== 'closed').length;
  const resolved = cases.filter((c) => c.status?.toLowerCase() === 'resolved').length;
  const openCases = cases.filter((c) => !['resolved', 'closed'].includes(c.status?.toLowerCase() || '')).length;

  const recent = [...alerts].sort((a, b) => Date.parse(b.created_at || '') - Date.parse(a.created_at || '')).slice(0, 8);
  const recentCases = [...cases].sort((a, b) => Date.parse(b.created_at || '') - Date.parse(a.created_at || '')).slice(0, 5);

  return (
    <>
      <div className="page-hd">
        <div>
          <h1>Dashboard</h1>
          <div className="page-meta">Security Operations Center · Live data</div>
        </div>
        <a href="/alerts" className="btn btn-primary">+ New Alert</a>
      </div>

      <div className="kpi-row">
        <div className="kpi-box red">
          <div className="kpi-label">Critical Alerts</div>
          <div className="kpi-value">{critical}</div>
          <div className="kpi-sub">Requires immediate action</div>
        </div>
        <div className="kpi-box amber">
          <div className="kpi-label">Open Alerts</div>
          <div className="kpi-value">{open}</div>
          <div className="kpi-sub">Pending triage</div>
        </div>
        <div className="kpi-box blue">
          <div className="kpi-label">Open Cases</div>
          <div className="kpi-value">{openCases}</div>
          <div className="kpi-sub">Active investigations</div>
        </div>
        <div className="kpi-box green">
          <div className="kpi-label">Resolved Cases</div>
          <div className="kpi-value">{resolved}</div>
          <div className="kpi-sub">Closed this session</div>
        </div>
      </div>

      {ops ? (
        <div className="card mb-4" style={{ padding: 14 }}>
          <div className="card-title mb-2 flex gap-2 items-center flex-wrap">
            Platform health
            <Link href="/operations" style={{ fontSize: 11, fontWeight: 400 }}>
              Details →
            </Link>
          </div>
          {(() => {
            const svc = ops.services || [];
            const up = svc.filter((x) => x.ok).length;
            const dbOk = ops.gateway_database?.ok !== false;
            const allOk = dbOk && svc.length > 0 && svc.every((x) => x.ok);
            return (
              <div className="flex gap-4 flex-wrap" style={{ fontSize: 13 }}>
                <div>
                  <span className="text-muted">Microservices</span>{' '}
                  <strong>
                    {up}/{svc.length} up
                  </strong>
                  {!allOk && svc.some((x) => !x.ok) ? (
                    <span className="badge badge-high" style={{ marginLeft: 8 }}>
                      degraded
                    </span>
                  ) : (
                    <span className="badge badge-resolved" style={{ marginLeft: 8 }}>
                      ok
                    </span>
                  )}
                </div>
                <div>
                  <span className="text-muted">Gateway DB</span>{' '}
                  {dbOk ? <span className="badge badge-resolved">ok</span> : <span className="badge badge-high">down</span>}
                </div>
                <div className="text-muted" style={{ fontSize: 11 }}>
                  Checked {ops.generated_at || '—'}
                </div>
              </div>
            );
          })()}
        </div>
      ) : null}

      {soc ? (
        <div className="card mb-4" style={{ padding: 14 }}>
          <div className="card-title mb-2">SOC summary <span className="text-muted" style={{ fontWeight: 400, fontSize: 11 }}>(API)</span></div>
          <div className="flex gap-4 flex-wrap" style={{ fontSize: 13 }}>
            <div>
              <span className="text-muted">Avg alert risk</span>{' '}
              <strong>{soc.alerts?.avg_risk_score ?? '—'}</strong>
            </div>
            <div>
              <span className="text-muted">Alerts (open / total)</span>{' '}
              <strong>{soc.alerts?.open ?? '—'}</strong> / {soc.alerts?.total ?? '—'}
            </div>
            <div>
              <span className="text-muted">Cases on legal hold</span>{' '}
              <strong>{soc.cases?.legal_hold ?? 0}</strong>
            </div>
            <div>
              <span className="text-muted">MTTR (resolved)</span>{' '}
              <strong>{soc.cases?.mttr_resolved_hours != null ? `${soc.cases.mttr_resolved_hours}h` : '—'}</strong>
            </div>
            <Link href="/hunting" style={{ fontSize: 12 }}>Hunting →</Link>
          </div>
          {soc.alerts?.by_source && Object.keys(soc.alerts.by_source).length > 0 ? (
            <div className="text-muted mt-2" style={{ fontSize: 11 }}>
              By source:{' '}
              {Object.entries(soc.alerts.by_source)
                .slice(0, 6)
                .map(([k, v]) => `${k}: ${v}`)
                .join(' · ')}
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="two-col">
        <div>
          <div className="card-header">
            <span className="card-title">Recent Alerts</span>
            <a href="/alerts" className="btn" style={{ fontSize: 11 }}>View all →</a>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 14 }}></th>
                <th>Title</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Status</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((a) => (
                <tr key={a.id}>
                  <td><span className={`indicator ind-${(a.severity || 'medium').toLowerCase()}`}></span></td>
                  <td className="truncate" style={{ maxWidth: 280 }}>
                    <Link href={`/alerts/${a.id}`} style={{ color: 'var(--accent-blue)' }}>{a.title || 'Untitled'}</Link>
                  </td>
                  <td>{sevBadge(a.severity)}</td>
                  <td className="text-muted">{a.source || '—'}</td>
                  <td>{statusBadge(a.status)}</td>
                  <td className="text-muted">{relTime(a.created_at)}</td>
                </tr>
              ))}
              {!recent.length && (
                <tr>
                  <td colSpan={6} className="empty-state">
                    No alerts yet. Ingest from SIEM to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <div className="card-header">
              <span className="card-title">Recent Cases</span>
              <a href="/cases" className="btn" style={{ fontSize: 11 }}>View all →</a>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Status</th>
                  <th>Age</th>
                </tr>
              </thead>
              <tbody>
                {recentCases.map((c) => (
                  <tr key={c.id}>
                    <td><a href={`/cases/${c.id}`} style={{ color: 'var(--accent-blue)' }}>{c.title}</a></td>
                    <td>{statusBadge(c.status)}</td>
                    <td className="text-muted">{relTime(c.created_at)}</td>
                  </tr>
                ))}
                {!recentCases.length && (
                  <tr>
                    <td colSpan={3} className="empty-state">
                      No cases yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="card" style={{ padding: '14px', flex: 1 }}>
            <LiveFeed />
          </div>
        </div>
      </div>
    </>
  );
}
