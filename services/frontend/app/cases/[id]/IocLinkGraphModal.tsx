'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import { useEffect, useMemo, useState } from 'react';

type AlertHit = {
  id: string;
  title?: string;
  source?: string;
  severity?: string;
  status?: string;
  created_at?: string;
  case_id?: string;
  observables?: { type: string; value: string }[];
};

type ByIocResponse = {
  observable: { type: string; value: string };
  count: number;
  alerts: AlertHit[];
};

function layoutRing(cx: number, cy: number, r: number, n: number): { x: number; y: number }[] {
  if (n <= 0) return [];
  return Array.from({ length: n }, (_, i) => {
    const ang = (2 * Math.PI * i) / n - Math.PI / 2;
    return { x: cx + r * Math.cos(ang), y: cy + r * Math.sin(ang) };
  });
}

function iocKey(t: string, v: string) {
  return `${t}:${v}`;
}

export default function IocLinkGraphModal({
  open,
  onClose,
  iocType,
  iocValue,
}: {
  open: boolean;
  onClose: () => void;
  iocType: string;
  iocValue: string;
}) {
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const [data, setData] = useState<ByIocResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setData(null);
      setErr('');
      setSelectedId(null);
      return;
    }
    setLoading(true);
    setErr('');
    setData(null);
    setSelectedId(null);
    const q = new URLSearchParams({
      type: iocType,
      value: iocValue,
      limit: '50',
    });
    void fetch(`${CLIENT_API_PREFIX}/alerts/alerts/by-observable?${q}`, { credentials: 'include' })
      .then(async (r) => {
        const j = (await r.json().catch(() => ({}))) as { detail?: string } & Partial<ByIocResponse>;
        if (!r.ok) {
          throw new Error(typeof j.detail === 'string' ? j.detail : `Request failed (${r.status})`);
        }
        return j as ByIocResponse;
      })
      .then(setData)
      .catch((e: Error) => setErr(e.message || 'Failed to load'))
      .finally(() => setLoading(false));
  }, [open, iocType, iocValue]);

  const centerKey = useMemo(() => iocKey(iocType, iocValue), [iocType, iocValue]);

  const bridging = useMemo(() => {
    if (!data?.alerts?.length) return [];
    const m = new Map<string, { type: string; value: string; alertIds: Set<string> }>();
    for (const a of data.alerts) {
      for (const o of a.observables || []) {
        const k = iocKey(o.type, o.value);
        if (k === centerKey) continue;
        let row = m.get(k);
        if (!row) {
          row = { type: o.type, value: o.value, alertIds: new Set() };
          m.set(k, row);
        }
        row.alertIds.add(a.id);
      }
    }
    return [...m.values()]
      .map((x) => ({ type: x.type, value: x.value, n: x.alertIds.size }))
      .filter((x) => x.n >= 2)
      .sort((a, b) => b.n - a.n)
      .slice(0, 14);
  }, [data, centerKey]);

  const layout = useMemo(() => {
    const n = data?.alerts?.length ?? 0;
    const cx = 260;
    const cy = 220;
    const r = n <= 1 ? 0 : Math.min(160, 70 + n * 8);
    return { cx, cy, r, pts: layoutRing(cx, cy, r, n) };
  }, [data?.alerts?.length]);

  const selected = data?.alerts?.find((a) => a.id === selectedId) ?? null;

  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
          <div>
            IOC → alerts graph
            <div className="text-muted" style={{ fontSize: 12, fontWeight: 400, marginTop: 4 }}>
              <span className="badge badge-info" style={{ fontSize: 10 }}>{iocType}</span>{' '}
              <span className="mono" style={{ wordBreak: 'break-all' }}>{iocValue}</span>
            </div>
          </div>
          <button type="button" className="btn" style={{ fontSize: 12 }} onClick={onClose}>
            Close
          </button>
        </div>

        {loading && <div className="empty-state">Loading correlated alerts…</div>}
        {err && (
          <div className="card" style={{ padding: 12, borderColor: 'var(--sev-high)', fontSize: 13 }}>
            {err}
          </div>
        )}

        {!loading && !err && data && (
          <>
            <p className="text-muted mb-2" style={{ fontSize: 12 }}>
              {data.count === 0
                ? 'No other alerts in the current store contain this IOC.'
                : `${data.count} alert${data.count === 1 ? '' : 's'} share this observable (showing up to ${data.alerts.length}). Center = IOC; ring = alerts. Click a node for details.`}
            </p>

            {data.alerts.length > 0 ? (
              <div className="card mb-3" style={{ padding: 12, overflow: 'auto' }}>
                <svg
                  width="100%"
                  viewBox="0 0 520 440"
                  style={{ maxHeight: 440, display: 'block' }}
                >
                  {data.alerts.map((a, i) => {
                    const p = layout.pts[i];
                    if (!p) return null;
                    return (
                      <line
                        key={`e-${a.id}`}
                        x1={layout.cx}
                        y1={layout.cy}
                        x2={p.x}
                        y2={p.y}
                        stroke="var(--border-subtle)"
                        strokeWidth={selectedId === a.id ? 2 : 1}
                        opacity={0.85}
                      />
                    );
                  })}
                  <circle
                    cx={layout.cx}
                    cy={layout.cy}
                    r={28}
                    fill="var(--accent-blue)"
                    opacity={0.25}
                    stroke="var(--accent-blue)"
                    strokeWidth={2}
                  />
                  <text
                    x={layout.cx}
                    y={layout.cy + 4}
                    textAnchor="middle"
                    fontSize={11}
                    fill="var(--text-primary)"
                    style={{ fontWeight: 600 }}
                  >
                    IOC
                  </text>
                  {data.alerts.map((a, i) => {
                    const p = layout.pts[i];
                    if (!p) return null;
                    const sel = selectedId === a.id;
                    return (
                      <g
                        key={a.id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => setSelectedId(sel ? null : a.id)}
                      >
                        <circle
                          cx={p.x}
                          cy={p.y}
                          r={sel ? 22 : 18}
                          fill={sel ? 'var(--accent-amber)' : 'var(--bg-elevated)'}
                          stroke={sel ? 'var(--accent-amber)' : 'var(--border-subtle)'}
                          strokeWidth={sel ? 2 : 1}
                        />
                        <text
                          x={p.x}
                          y={p.y + 4}
                          textAnchor="middle"
                          fontSize={9}
                          fill="var(--text-primary)"
                          className="mono"
                        >
                          {a.id.slice(0, 6)}…
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            ) : null}

            {bridging.length > 0 ? (
              <div className="card mb-3" style={{ padding: 12 }}>
                <div className="card-title mb-2" style={{ fontSize: 13 }}>
                  Other IOCs linking multiple of these alerts
                </div>
                <p className="text-muted mb-2" style={{ fontSize: 11 }}>
                  Shown when the same observable appears in at least two alerts from the set above (correlation hints).
                </p>
                <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                  {bridging.map((b) => (
                    <span
                      key={`${b.type}:${b.value}`}
                      className="obs-chip"
                      title={`${b.value} · ${b.n} alerts`}
                    >
                      <span className="obs-chip-type">{b.type}</span>
                      <span style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{b.value}</span>
                      <span className="text-muted" style={{ fontSize: 10, marginLeft: 4 }}>({b.n})</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="card-title" style={{ padding: '10px 12px', margin: 0, borderBottom: '1px solid var(--border-subtle)' }}>
                Alert list
              </div>
              <table className="data-table" style={{ margin: 0 }}>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {data.alerts.map((a) => (
                    <tr
                      key={a.id}
                      style={{ cursor: 'pointer', background: selectedId === a.id ? 'var(--bg-elevated)' : undefined }}
                      onClick={() => setSelectedId(selectedId === a.id ? null : a.id)}
                    >
                      <td className="mono" style={{ fontSize: 11 }}>
                        <Link href={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()}>
                          {a.id.slice(0, 10)}…
                        </Link>
                      </td>
                      <td style={{ fontSize: 12 }}>{a.title || '—'}</td>
                      <td className="text-muted" style={{ fontSize: 11 }}>{a.source || '—'}</td>
                      <td><span className={`badge badge-${(a.severity || 'medium').toLowerCase()}`}>{a.severity || '—'}</span></td>
                      <td className="text-muted" style={{ fontSize: 11 }}>{a.created_at?.slice(0, 19) || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selected ? (
              <div className="card mt-3" style={{ padding: 14 }}>
                <div className="card-title mb-2" style={{ fontSize: 13 }}>Selected alert detail</div>
                <dl className="alert-detail-kv" style={{ fontSize: 12 }}>
                  <dt>ID</dt>
                  <dd className="mono">
                    <Link href={`/alerts/${selected.id}`}>{selected.id}</Link>
                  </dd>
                  <dt>Title</dt>
                  <dd>{selected.title || '—'}</dd>
                  <dt>Status</dt>
                  <dd>{selected.status || '—'}</dd>
                  <dt>Case</dt>
                  <dd>
                    {selected.case_id ? (
                      <Link href={`/cases/${selected.case_id}`}>{selected.case_id}</Link>
                    ) : (
                      '—'
                    )}
                  </dd>
                </dl>
                <div className="card-title mt-3 mb-1" style={{ fontSize: 12 }}>All observables on this alert</div>
                <div className="obs-chips">
                  {(selected.observables || []).map((o, j) => (
                    <span className="obs-chip" key={`${o.type}-${j}`}>
                      <span className="obs-chip-type">{o.type}</span>
                      <span style={{ wordBreak: 'break-all' }}>{o.value}</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}
