'use client';

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

const BASE = process.env.NEXT_PUBLIC_API_GATEWAY_URL || 'http://localhost:8000';

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

async function fetchJson<T>(path: string, token: string | null): Promise<T> {
  if (!token) return [] as T;
  try {
    const res = await fetch(`${BASE}${path}`, {
      cache: 'no-store',
      headers: { authorization: `Bearer ${token}` },
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
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('sirp_token') : null;
    const [a, c] = await Promise.all([
      fetchJson<AlertItem[]>('/alerts/alerts', token),
      fetchJson<CaseItem[]>('/cases/cases', token),
    ]);
    setAlerts(Array.isArray(a) ? a : []);
    setCases(Array.isArray(c) ? c : []);
    setLoaded(true);
  }, []);

  useEffect(() => {
    load();
    const onStorage = (e: StorageEvent) => {
      if (e.key === 'sirp_token') load();
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [load]);

  const critical = alerts.filter((a) => a.severity?.toLowerCase() === 'critical').length;
  const open = alerts.filter((a) => a.status?.toLowerCase() !== 'closed').length;
  const resolved = cases.filter((c) => c.status?.toLowerCase() === 'resolved').length;
  const openCases = cases.filter((c) => !['resolved', 'closed'].includes(c.status?.toLowerCase() || '')).length;

  const recent = [...alerts].sort((a, b) => Date.parse(b.created_at || '') - Date.parse(a.created_at || '')).slice(0, 8);
  const recentCases = [...cases].sort((a, b) => Date.parse(b.created_at || '') - Date.parse(a.created_at || '')).slice(0, 5);

  const noToken = loaded && typeof window !== 'undefined' && !localStorage.getItem('sirp_token');

  return (
    <>
      <div className="page-hd">
        <div>
          <h1>Dashboard</h1>
          <div className="page-meta">Security Operations Center · Live data</div>
        </div>
        <a href="/alerts" className="btn btn-primary">+ New Alert</a>
      </div>

      {noToken && (
        <p className="text-muted mb-4" style={{ fontSize: 13 }}>
          Sign in to load alerts and cases.{' '}
          <a href="/login">Go to login</a>
        </p>
      )}

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
                  <td className="truncate" style={{ maxWidth: 280 }}>{a.title || 'Untitled'}</td>
                  <td>{sevBadge(a.severity)}</td>
                  <td className="text-muted">{a.source || '—'}</td>
                  <td>{statusBadge(a.status)}</td>
                  <td className="text-muted">{relTime(a.created_at)}</td>
                </tr>
              ))}
              {!recent.length && (
                <tr>
                  <td colSpan={6} className="empty-state">
                    {noToken ? 'Sign in to see alerts.' : 'No alerts yet. Ingest from SIEM to get started.'}
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
                      {noToken ? 'Sign in to see cases.' : 'No cases yet.'}
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
