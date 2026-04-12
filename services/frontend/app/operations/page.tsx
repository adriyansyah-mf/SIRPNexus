'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useCallback, useEffect, useRef, useState } from 'react';

type ServiceCheck = { service: string; ok: boolean; ms: number; error?: string | null };

type OpsPayload = {
  generated_at?: string;
  gateway_database?: { ok?: boolean };
  services?: ServiceCheck[];
};

type HistoryItem = {
  id: number;
  created_at?: string | null;
  snapshot: OpsPayload;
};

type HistoryResponse = { items?: HistoryItem[] };

function countUpDown(services: ServiceCheck[] | undefined): { up: number; down: number } {
  const list = services || [];
  const up = list.filter((s) => s.ok).length;
  return { up, down: list.length - up };
}

function isHealthy(data: OpsPayload | null): boolean {
  if (!data) return true;
  const dbOk = data.gateway_database?.ok !== false;
  const svc = data.services || [];
  return dbOk && svc.length > 0 && svc.every((s) => s.ok);
}

export default function OperationsPage() {
  const [data, setData] = useState<OpsPayload | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [autoSec, setAutoSec] = useState(0);
  const [notifHint, setNotifHint] = useState('');
  const prevHealthyRef = useRef<boolean | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setErr('');
    const [res, hres] = await Promise.all([
      fetch(`${CLIENT_API_PREFIX}/soc/ops-status`, { cache: 'no-store', credentials: 'include' }),
      fetch(`${CLIENT_API_PREFIX}/soc/ops-history?limit=48`, { cache: 'no-store', credentials: 'include' }),
    ]);
    if (!res.ok) {
      setErr(res.status === 401 ? 'Sign in required.' : `Failed (${res.status})`);
      setData(null);
      setHistory([]);
      setLoading(false);
      return;
    }
    const payload = (await res.json()) as OpsPayload;
    setData(payload);

    if (hres.ok) {
      const hjson = (await hres.json()) as HistoryResponse;
      setHistory(Array.isArray(hjson.items) ? hjson.items : []);
    } else {
      setHistory([]);
    }

    const healthy = isHealthy(payload);
    const prev = prevHealthyRef.current;
    if (prev === true && !healthy && typeof window !== 'undefined' && 'Notification' in window) {
      if (Notification.permission === 'granted') {
        try {
          new Notification('SIRP: platform degraded', {
            body: 'A service or gateway database failed the health check.',
          });
        } catch {
          /* ignore */
        }
      }
    }
    prevHealthyRef.current = healthy;

    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (autoSec <= 0) return;
    const t = window.setInterval(() => void load(), autoSec * 1000);
    return () => window.clearInterval(t);
  }, [autoSec, load]);

  const requestNotif = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setNotifHint('Notifications not supported in this browser.');
      return;
    }
    const p = await Notification.requestPermission();
    setNotifHint(p === 'granted' ? 'Desktop alerts enabled when status worsens.' : `Permission: ${p}`);
  };

  const degraded = data ? !isHealthy(data) : false;
  const { up: upNow, down: downNow } = countUpDown(data?.services);

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Operations status</h1>
          <div className="page-meta">Service health via API gateway · snapshots every ~3 min when polled</div>
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          <label className="text-muted" style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            Auto-refresh
            <select
              value={autoSec}
              onChange={(e) => setAutoSec(Number(e.target.value))}
              style={{ fontSize: 12 }}
            >
              <option value={0}>Off</option>
              <option value={30}>30s</option>
              <option value={60}>60s</option>
            </select>
          </label>
          <button type="button" onClick={requestNotif} style={{ fontSize: 12 }}>
            Desktop alerts
          </button>
          <button type="button" onClick={() => void load()} disabled={loading}>
            ↻ Refresh
          </button>
        </div>
      </div>

      {notifHint ? (
        <p className="text-muted mb-2" style={{ fontSize: 12 }}>
          {notifHint}
        </p>
      ) : null}

      {degraded && data ? (
        <div
          className="card mb-3"
          style={{
            padding: 12,
            borderColor: 'var(--sev-high)',
            background: 'color-mix(in srgb, var(--sev-high) 12%, transparent)',
          }}
        >
          <strong>Degraded</strong>
          <span className="text-muted" style={{ fontSize: 13, marginLeft: 8 }}>
            {data.gateway_database?.ok === false ? 'Gateway PostgreSQL unreachable. ' : null}
            {(data.services || []).filter((s) => !s.ok).map((s) => s.service).join(', ') || null}
          </span>
        </div>
      ) : null}

      {err ? <div className="card mb-3" style={{ padding: 12, borderColor: 'var(--sev-high)' }}>{err}</div> : null}

      {loading && !data ? <div className="empty-state">Loading…</div> : null}

      {data ? (
        <>
          <div className="card mb-4" style={{ padding: 14 }}>
            <div className="card-title mb-2">Gateway</div>
            <p style={{ fontSize: 13, margin: 0 }}>
              <strong>PostgreSQL (users / audit / hunts / ops history)</strong>:{' '}
              {data.gateway_database?.ok ? (
                <span className="badge badge-resolved">ok</span>
              ) : (
                <span className="badge badge-high">unreachable</span>
              )}
            </p>
            <p className="text-muted mt-2" style={{ fontSize: 11, margin: 0 }}>
              Generated {data.generated_at || '—'} · microservices up {upNow} / {(data.services || []).length}
              {downNow ? ` · ${downNow} down` : ''}
            </p>
          </div>

          <table className="data-table mb-4">
            <thead>
              <tr>
                <th>Service</th>
                <th>Status</th>
                <th>Latency</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {(data.services || []).map((s) => (
                <tr key={s.service}>
                  <td className="mono" style={{ fontSize: 13 }}>
                    {s.service}
                  </td>
                  <td>
                    {s.ok ? (
                      <span className="badge badge-resolved">up</span>
                    ) : (
                      <span className="badge badge-high">down</span>
                    )}
                  </td>
                  <td className="text-muted">{s.ms} ms</td>
                  <td className="text-muted mono" style={{ fontSize: 11 }}>
                    {s.error || '—'}
                  </td>
                </tr>
              ))}
              {!data.services?.length && (
                <tr>
                  <td colSpan={4}>
                    <div className="empty-state">No service rows.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {history.length > 0 ? (
            <div className="card mb-4" style={{ padding: 14 }}>
              <div className="card-title mb-2">Recent snapshots</div>
              <p className="text-muted mb-3" style={{ fontSize: 11, marginTop: 0 }}>
                Stored automatically (throttled) when this page or other clients call ops-status.{' '}
                <Link href="/" style={{ fontSize: 11 }}>
                  Dashboard
                </Link>{' '}
                also polls for the health widget.
              </p>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Recorded</th>
                    <th>Up / total</th>
                    <th>DB</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((row) => {
                    const snap = row.snapshot || {};
                    const svc = snap.services || [];
                    const { up, down } = countUpDown(svc);
                    const db = snap.gateway_database?.ok !== false;
                    return (
                      <tr key={row.id}>
                        <td className="text-muted" style={{ fontSize: 12 }}>
                          {row.created_at || '—'}
                        </td>
                        <td style={{ fontSize: 12 }}>
                          <span className={down ? 'badge badge-high' : 'badge badge-resolved'}>
                            {up}/{svc.length}
                          </span>
                          {down ? <span className="text-muted"> ({down} down)</span> : null}
                        </td>
                        <td>{db ? <span className="badge badge-resolved">ok</span> : <span className="badge badge-high">fail</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : !loading ? (
            <p className="text-muted mb-4" style={{ fontSize: 12 }}>
              No history rows yet — refresh a few times (every ~3 minutes new snapshot is stored).
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
