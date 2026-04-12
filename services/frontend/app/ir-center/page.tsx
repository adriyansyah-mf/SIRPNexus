'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useCallback, useEffect, useMemo, useState } from 'react';

type Tab =
  | 'graph'
  | 'bundle'
  | 'shift'
  | 'custody'
  | 'approvals'
  | 'analytics'
  | 'retro'
  | 'watch'
  | 'enrich'
  | 'mentions';

type GraphNode = { id: string; kind: string; label: string };
type GraphEdge = { from: string; to: string; rel: string };

function GraphCanvas({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const layout = useMemo(() => {
    const n = Math.max(nodes.length, 1);
    const cx = 320;
    const cy = 220;
    const r = 160;
    const pos = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, i) => {
      const ang = (2 * Math.PI * i) / n - Math.PI / 2;
      pos.set(node.id, { x: cx + r * Math.cos(ang), y: cy + r * Math.sin(ang) });
    });
    return { pos, cx, cy };
  }, [nodes]);

  const color = (k: string) =>
    k === 'case' ? 'var(--accent-blue)' : k === 'alert' ? 'var(--sev-high)' : 'var(--text-muted)';

  return (
    <svg width="100%" height={440} style={{ background: 'var(--bg-base)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
      {edges.map((e, i) => {
        const a = layout.pos.get(e.from);
        const b = layout.pos.get(e.to);
        if (!a || !b) return null;
        return (
          <line
            key={i}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="var(--border-subtle)"
            strokeWidth={1}
          />
        );
      })}
      {nodes.map((node) => {
        const p = layout.pos.get(node.id);
        if (!p) return null;
        return (
          <g key={node.id} transform={`translate(${p.x},${p.y})`}>
            <circle r={26} fill="var(--bg-elevated)" stroke={color(node.kind)} strokeWidth={2} />
            <title>{node.id}</title>
            <text textAnchor="middle" dy={4} fontSize={9} fill="var(--text-primary)">
              {(node.label || node.kind).slice(0, 14)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export default function IrCenterPage() {
  const [tab, setTab] = useState<Tab>('graph');
  const [graphCaseId, setGraphCaseId] = useState('');
  const [graphAlertId, setGraphAlertId] = useState('');
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [bundleCaseId, setBundleCaseId] = useState('');
  const [shiftSummary, setShiftSummary] = useState('');
  const [shiftCases, setShiftCases] = useState('');
  const [shiftAlerts, setShiftAlerts] = useState('');
  const [shifts, setShifts] = useState<{ id: string; author: string; summary: string; created_at?: string }[]>([]);
  const [custodyCase, setCustodyCase] = useState('');
  const [custodyItems, setCustodyItems] = useState<
    { id: number; at?: string; actor: string; action: string; case_id?: string }[]
  >([]);
  const [analytics, setAnalytics] = useState<Record<string, unknown> | null>(null);
  const [retroQ, setRetroQ] = useState('');
  const [retroHits, setRetroHits] = useState<unknown[]>([]);
  const [watchItems, setWatchItems] = useState<{ case_id: string; created_at?: string }[]>([]);
  const [watchAdd, setWatchAdd] = useState('');
  const [pbRequests, setPbRequests] = useState<
    {
      id: string;
      playbook_id: string;
      requester: string;
      status: string;
      case_id?: string;
      created_at?: string;
      current_step?: number;
      approval_chain?: unknown;
    }[]
  >([]);
  const [pbId, setPbId] = useState('');
  const [pbCase, setPbCase] = useState('');
  const [pbChainJson, setPbChainJson] = useState('[{"role":"responder"},{"role":"admin"}]');
  const [siemQ, setSiemQ] = useState('');
  const [siemIdx, setSiemIdx] = useState('');
  const [siemOut, setSiemOut] = useState<Record<string, unknown> | null>(null);
  const [mentionItems, setMentionItems] = useState<
    { id: number; at?: string; case_id: string; author: string; excerpt?: string }[]
  >([]);
  const [indexedGraph, setIndexedGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [enrichAlert, setEnrichAlert] = useState('');
  const [enrichOut, setEnrichOut] = useState<unknown[]>([]);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const c = new URLSearchParams(window.location.search).get('case');
    if (c) {
      setGraphCaseId(c);
      setBundleCaseId(c);
    }
  }, []);

  const postJson = useMemo(
    (): RequestInit => ({ credentials: 'include', headers: { 'content-type': 'application/json' } }),
    [],
  );

  const loadGraph = useCallback(async () => {
    setErr('');
    setMsg('');
    const qs = new URLSearchParams();
    if (graphCaseId.trim()) qs.set('case_id', graphCaseId.trim());
    if (graphAlertId.trim()) qs.set('alert_id', graphAlertId.trim());
    if (!qs.toString()) {
      setErr('Enter case_id and/or alert_id');
      return;
    }
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/investigation-graph?${qs}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setGraphData(null);
      setErr(`Graph failed (${res.status})`);
      return;
    }
    const d = (await res.json()) as { nodes?: GraphNode[]; edges?: GraphEdge[] };
    setGraphData({ nodes: d.nodes || [], edges: d.edges || [] });
    setMsg('Graph loaded');
  }, [graphCaseId, graphAlertId]);

  const loadIndexedGraph = async () => {
    setErr('');
    setIndexedGraph(null);
    const fk = graphCaseId.trim() ? 'case' : graphAlertId.trim() ? 'alert' : '';
    const fid = graphCaseId.trim() || graphAlertId.trim();
    if (!fk || !fid) {
      setErr('Set case or alert UUID for indexed graph');
      return;
    }
    const qs = new URLSearchParams({ focus_kind: fk, focus_id: fid, limit: '300' });
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/graph/neighbors?${qs}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setErr(`Indexed graph failed (${res.status}) — run Reindex as admin first`);
      return;
    }
    const d = (await res.json()) as { nodes?: GraphNode[]; edges?: GraphEdge[] };
    setIndexedGraph({ nodes: d.nodes || [], edges: d.edges || [] });
    setMsg('Indexed graph loaded (Postgres sirp_entity_edges)');
  };

  const runGraphReindex = async () => {
    setErr('');
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/graph/reindex`, {
      method: 'POST',
      credentials: 'include',
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      setErr(typeof j.detail === 'string' ? j.detail : `Reindex failed (${res.status}) — admin only`);
      return;
    }
    setMsg(`Reindexed ${(j as { edges_upserted?: number }).edges_upserted ?? 0} edges`);
  };

  const loadMyMentions = async () => {
    setErr('');
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/mentions/for-me?limit=60`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setErr(`Mentions failed (${res.status})`);
      return;
    }
    const j = (await res.json()) as { items?: typeof mentionItems };
    setMentionItems(j.items || []);
  };

  const runSiemRetro = async () => {
    setErr('');
    if (siemQ.trim().length < 2) {
      setErr('SIEM query at least 2 characters');
      return;
    }
    const qs = new URLSearchParams({ q: siemQ.trim(), size: '40' });
    if (siemIdx.trim()) qs.set('index', siemIdx.trim());
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/retro-hunt/siem?${qs}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      setErr(typeof (j as { detail?: string }).detail === 'string' ? (j as { detail: string }).detail : `SIEM failed (${res.status})`);
      setSiemOut(null);
      return;
    }
    setSiemOut(j as Record<string, unknown>);
  };

  const downloadBundle = async () => {
    setErr('');
    if (!bundleCaseId.trim()) {
      setErr('Case ID required');
      return;
    }
    const res = await fetch(
      `${CLIENT_API_PREFIX}/soc/investigation-bundle?case_id=${encodeURIComponent(bundleCaseId.trim())}`,
      { cache: 'no-store', credentials: 'include' },
    );
    if (!res.ok) {
      setErr(`Bundle failed (${res.status})`);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ir-bundle-${bundleCaseId.trim().slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setMsg('Bundle downloaded (custody logged server-side)');
  };

  const submitShift = async () => {
    setErr('');
    if (shiftSummary.trim().length < 3) {
      setErr('Summary too short');
      return;
    }
    const case_ids = shiftCases.split(/[\s,]+/).filter(Boolean);
    const alert_ids = shiftAlerts.split(/[\s,]+/).filter(Boolean);
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/shift-report`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({ summary: shiftSummary, case_ids, alert_ids }),
    });
    if (!res.ok) {
      setErr(`Shift report failed (${res.status})`);
      return;
    }
    setShiftSummary('');
    setShiftCases('');
    setShiftAlerts('');
    setMsg('Shift report saved');
    const lr = await fetch(`${CLIENT_API_PREFIX}/soc/shift-reports?limit=20`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (lr.ok) {
      const j = (await lr.json()) as { items?: typeof shifts };
      setShifts(j.items || []);
    }
  };

  const loadCustody = async () => {
    setErr('');
    const qs = custodyCase.trim() ? `?case_id=${encodeURIComponent(custodyCase.trim())}&limit=80` : '?limit=80';
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/custody-log${qs}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setErr(`Custody list failed (${res.status})`);
      return;
    }
    const j = (await res.json()) as { items?: typeof custodyItems };
    setCustodyItems(j.items || []);
  };

  const loadAnalytics = async () => {
    setErr('');
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/analytics-advanced`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setErr(`Analytics failed (${res.status})`);
      return;
    }
    setAnalytics((await res.json()) as Record<string, unknown>);
  };

  const runRetro = async () => {
    setErr('');
    if (retroQ.trim().length < 2) {
      setErr('Query at least 2 chars');
      return;
    }
    const res = await fetch(
      `${CLIENT_API_PREFIX}/soc/retro-hunt?q=${encodeURIComponent(retroQ.trim())}&limit=50`,
      { cache: 'no-store', credentials: 'include' },
    );
    if (!res.ok) {
      setErr(`Retro-hunt failed (${res.status})`);
      return;
    }
    const j = (await res.json()) as { matches?: unknown[] };
    setRetroHits(j.matches || []);
    setMsg(`Scanned observables`);
  };

  const loadWatch = async () => {
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/watchlist`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (res.ok) {
      const j = (await res.json()) as { items?: typeof watchItems };
      setWatchItems(j.items || []);
    }
  };

  const addWatch = async () => {
    if (!watchAdd.trim()) return;
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/watchlist`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({ case_id: watchAdd.trim() }),
    });
    if (res.ok) {
      setWatchAdd('');
      setMsg('Watching case');
      void loadWatch();
    } else setErr('Watch add failed');
  };

  const removeWatch = async (cid: string) => {
    await fetch(`${CLIENT_API_PREFIX}/soc/watchlist/${encodeURIComponent(cid)}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    void loadWatch();
  };

  const loadApprovals = async () => {
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/playbook-run-requests?status=pending&limit=50`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (res.ok) {
      const j = (await res.json()) as { items?: typeof pbRequests };
      setPbRequests(j.items || []);
    }
  };

  const requestPb = async () => {
    if (!pbId.trim()) {
      setErr('Playbook id required');
      return;
    }
    let approval_chain: unknown;
    try {
      approval_chain = JSON.parse(pbChainJson || '[]');
    } catch {
      setErr('approval_chain must be valid JSON array');
      return;
    }
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/playbook-run-requests`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({
        playbook_id: pbId.trim(),
        case_id: pbCase.trim() || undefined,
        event: {},
        approval_chain,
      }),
    });
    if (res.ok) {
      setMsg('Approval request queued');
      void loadApprovals();
    } else setErr('Request failed (need analyst+ role)');
  };

  const approvePb = async (id: string) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/playbook-run-requests/${id}/approve`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({}),
    });
    const data = (await res.json().catch(() => ({}))) as {
      status?: string;
      current_step?: number;
      total_steps?: number;
    };
    if (res.ok) {
      if (data.status === 'pending_next_step') {
        setMsg(`Step OK — now ${data.current_step}/${data.total_steps} (approve again for next role)`);
      } else {
        setMsg('Playbook executed');
      }
    } else setErr('Approve failed (wrong role for this step?)');
    void loadApprovals();
  };

  const rejectPb = async (id: string) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/playbook-run-requests/${id}/reject`, {
      method: 'POST',
      ...postJson,
      body: JSON.stringify({ note: 'rejected from IR center' }),
    });
    if (res.ok) setMsg('Rejected');
    else setErr('Reject failed');
    void loadApprovals();
  };

  const loadEnrich = async () => {
    if (!enrichAlert.trim()) return;
    const res = await fetch(
      `${CLIENT_API_PREFIX}/soc/enrichment-hints?alert_id=${encodeURIComponent(enrichAlert.trim())}`,
      { cache: 'no-store', credentials: 'include' },
    );
    if (res.ok) {
      const j = (await res.json()) as { hints?: unknown[] };
      setEnrichOut(j.hints || []);
    } else setErr('Enrichment hints failed');
  };

  useEffect(() => {
    void fetch(`${CLIENT_API_PREFIX}/soc/shift-reports?limit=15`, {
      cache: 'no-store',
      credentials: 'include',
    })
      .then((r) => r.json())
      .then((j: { items?: typeof shifts }) => setShifts(j.items || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (tab === 'watch') void loadWatch();
    if (tab === 'approvals') void loadApprovals();
    if (tab === 'mentions') void loadMyMentions();
  }, [tab]);

  const tabs: { id: Tab; label: string }[] = [
    { id: 'graph', label: 'Investigation graph' },
    { id: 'bundle', label: 'IR bundle' },
    { id: 'shift', label: 'Shift handover' },
    { id: 'custody', label: 'Chain of custody' },
    { id: 'approvals', label: 'Playbook approval' },
    { id: 'mentions', label: '@Mentions' },
    { id: 'analytics', label: 'SOC analytics+' },
    { id: 'retro', label: 'Retro-hunt' },
    { id: 'watch', label: 'Case watchlist' },
    { id: 'enrich', label: 'Intel hints' },
  ];

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>IR command center</h1>
          <div className="page-meta">
            Unified ops: graph, bundles, shift logs, custody, gated playbook runs, analytics, IOC back-search, watchlist,
            enrichment hints
          </div>
        </div>
      </div>

      {err ? (
        <div className="card mb-3" style={{ padding: 10, borderColor: 'var(--sev-high)' }}>
          {err}
        </div>
      ) : null}
      {msg ? (
        <div className="card mb-3" style={{ padding: 10, borderColor: 'var(--accent-blue)' }}>
          {msg}
        </div>
      ) : null}

      <div className="flex gap-1 mb-4 flex-wrap" style={{ alignItems: 'center' }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => {
              setErr('');
              setMsg('');
              setTab(t.id);
            }}
            style={{
              fontSize: 12,
              padding: '6px 10px',
              borderRadius: 4,
              border: '1px solid var(--border-subtle)',
              background: tab === t.id ? 'var(--accent-blue)' : 'var(--bg-elevated)',
              color: tab === t.id ? '#fff' : 'var(--text-primary)',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'graph' && (
        <div className="card" style={{ padding: 14 }}>
          <p className="text-muted" style={{ fontSize: 12, marginTop: 0 }}>
            Case-centric graph: linked cases, source alert, shared observables.
          </p>
          <div className="flex gap-2 mb-2 flex-wrap">
            <input
              placeholder="Case UUID"
              value={graphCaseId}
              onChange={(e) => setGraphCaseId(e.target.value)}
              className="w-full"
              style={{ maxWidth: 360 }}
            />
            <input
              placeholder="Alert UUID (optional if case set)"
              value={graphAlertId}
              onChange={(e) => setGraphAlertId(e.target.value)}
              className="w-full"
              style={{ maxWidth: 360 }}
            />
            <button type="button" onClick={() => void loadGraph()}>
              Load live graph
            </button>
            <button type="button" onClick={() => void loadIndexedGraph()}>
              Load indexed graph
            </button>
            <button type="button" onClick={() => void runGraphReindex()}>
              Reindex edges (admin)
            </button>
          </div>
          <p className="text-muted" style={{ fontSize: 11 }}>
            Indexed graph uses <code className="mono">sirp_entity_edges</code> (reindex scans all cases/alerts). Live graph calls upstream APIs directly.
          </p>
          {graphData && graphData.nodes.length ? (
            <>
              <h4 style={{ fontSize: 12 }}>Live</h4>
              <GraphCanvas nodes={graphData.nodes} edges={graphData.edges} />
            </>
          ) : null}
          {indexedGraph && indexedGraph.nodes.length ? (
            <>
              <h4 style={{ fontSize: 12, marginTop: 12 }}>Indexed store</h4>
              <GraphCanvas nodes={indexedGraph.nodes} edges={indexedGraph.edges} />
            </>
          ) : null}
          {!graphData?.nodes.length && !indexedGraph?.nodes.length ? (
            <div className="empty-state">No graph data</div>
          ) : null}
        </div>
      )}

      {tab === 'bundle' && (
        <div className="card" style={{ padding: 14 }}>
          <p className="text-muted" style={{ fontSize: 12, marginTop: 0 }}>
            Full export + embedded graph + recent custody tail; download is logged automatically.
          </p>
          <div className="flex gap-2 items-center flex-wrap">
            <input
              placeholder="Case UUID"
              value={bundleCaseId}
              onChange={(e) => setBundleCaseId(e.target.value)}
              style={{ minWidth: 280 }}
            />
            <button type="button" className="btn-primary" onClick={() => void downloadBundle()}>
              Download IR JSON bundle
            </button>
          </div>
        </div>
      )}

      {tab === 'shift' && (
        <div className="card" style={{ padding: 14 }}>
          <label className="text-muted" style={{ fontSize: 12 }}>
            Handover summary
          </label>
          <textarea className="w-full mb-2" rows={4} value={shiftSummary} onChange={(e) => setShiftSummary(e.target.value)} />
          <label className="text-muted" style={{ fontSize: 12 }}>
            Case IDs (space/comma)
          </label>
          <input className="w-full mb-2" value={shiftCases} onChange={(e) => setShiftCases(e.target.value)} />
          <label className="text-muted" style={{ fontSize: 12 }}>
            Alert IDs (space/comma)
          </label>
          <input className="w-full mb-2" value={shiftAlerts} onChange={(e) => setShiftAlerts(e.target.value)} />
          <button type="button" className="btn-primary" onClick={() => void submitShift()}>
            Submit shift report
          </button>
          <h4 className="mt-4" style={{ fontSize: 13 }}>
            Recent reports
          </h4>
          <ul style={{ fontSize: 12, paddingLeft: 18 }}>
            {shifts.map((s) => (
              <li key={s.id} className="mb-2">
                <strong>{s.author}</strong> · {s.created_at}
                <div className="text-muted">{s.summary.slice(0, 200)}{s.summary.length > 200 ? '…' : ''}</div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'custody' && (
        <div className="card" style={{ padding: 14 }}>
          <div className="flex gap-2 mb-2 flex-wrap">
            <input
              placeholder="Filter by case ID (optional)"
              value={custodyCase}
              onChange={(e) => setCustodyCase(e.target.value)}
              style={{ minWidth: 260 }}
            />
            <button type="button" onClick={() => void loadCustody()}>
              Load log
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Case</th>
              </tr>
            </thead>
            <tbody>
              {custodyItems.map((c) => (
                <tr key={c.id}>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {c.at || '—'}
                  </td>
                  <td>{c.actor}</td>
                  <td>{c.action}</td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {c.case_id || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!custodyItems.length ? <div className="empty-state">Load custody events</div> : null}
        </div>
      )}

      {tab === 'approvals' && (
        <div className="card" style={{ padding: 14 }}>
          <p className="text-muted" style={{ fontSize: 12, marginTop: 0 }}>
            Request gated execution of destructive SOAR actions. <strong>Responder / admin</strong> approves → automation
            service runs the playbook.
          </p>
          <div className="flex gap-2 mb-2 flex-wrap">
            <input placeholder="playbook_id" value={pbId} onChange={(e) => setPbId(e.target.value)} style={{ minWidth: 200 }} />
            <input placeholder="case_id (optional)" value={pbCase} onChange={(e) => setPbCase(e.target.value)} style={{ minWidth: 200 }} />
            <button type="button" onClick={() => void requestPb()}>
              Request run
            </button>
            <button type="button" onClick={() => void loadApprovals()}>
              Refresh pending
            </button>
          </div>
          <label className="text-muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>
            Multi-step approval chain (JSON array of {`{role}`} — e.g. responder then admin)
          </label>
          <textarea
            className="w-full mono mb-3"
            rows={2}
            value={pbChainJson}
            onChange={(e) => setPbChainJson(e.target.value)}
            style={{ fontSize: 11 }}
          />
          <table className="data-table">
            <thead>
              <tr>
                <th>Playbook</th>
                <th>Requester</th>
                <th>Case</th>
                <th>Step</th>
                <th>When</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pbRequests.map((p) => (
                <tr key={p.id}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {p.playbook_id}
                  </td>
                  <td>{p.requester}</td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {p.case_id || '—'}
                  </td>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {p.current_step != null && Array.isArray(p.approval_chain)
                      ? `${Number(p.current_step) + 1}/${p.approval_chain.length}`
                      : '—'}
                  </td>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {p.created_at || '—'}
                  </td>
                  <td>
                    <button type="button" style={{ fontSize: 11, marginRight: 6 }} onClick={() => void approvePb(p.id)}>
                      Approve step
                    </button>
                    <button type="button" style={{ fontSize: 11 }} onClick={() => void rejectPb(p.id)}>
                      Reject
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!pbRequests.length ? <div className="empty-state">No pending requests</div> : null}
        </div>
      )}

      {tab === 'analytics' && (
        <div className="card" style={{ padding: 14 }}>
          <button type="button" className="mb-3" onClick={() => void loadAnalytics()}>
            Load advanced analytics
          </button>
          {analytics ? (
            <pre
              className="mono"
              style={{ fontSize: 11, overflow: 'auto', maxHeight: 420, margin: 0 }}
            >
              {JSON.stringify(analytics, null, 2)}
            </pre>
          ) : (
            <div className="empty-state">Not loaded</div>
          )}
        </div>
      )}

      {tab === 'retro' && (
        <div className="card" style={{ padding: 14 }}>
          <h4 style={{ fontSize: 13, marginTop: 0 }}>Elasticsearch (full SIEM retro)</h4>
          <p className="text-muted" style={{ fontSize: 11, marginTop: 0 }}>
            Uses alert-service → Elasticsearch (<code className="mono">ELASTIC_SIEM_INDEX</code>, default{' '}
            <code className="mono">wazuh-alerts-*</code>).
          </p>
          <div className="flex gap-2 mb-2 flex-wrap">
            <input
              placeholder="Query (simple_query_string)"
              value={siemQ}
              onChange={(e) => setSiemQ(e.target.value)}
              className="w-full"
              style={{ maxWidth: 360 }}
            />
            <input
              placeholder="Index override (optional)"
              value={siemIdx}
              onChange={(e) => setSiemIdx(e.target.value)}
              style={{ maxWidth: 200 }}
            />
            <button type="button" onClick={() => void runSiemRetro()}>
              Search SIEM
            </button>
          </div>
          {siemOut ? (
            <pre className="mono mb-4" style={{ fontSize: 10, maxHeight: 240, overflow: 'auto' }}>
              {JSON.stringify(siemOut, null, 2)}
            </pre>
          ) : null}

          <h4 style={{ fontSize: 13 }}>Observable store (SIRP DB)</h4>
          <p className="text-muted" style={{ fontSize: 11 }}>
            Last ~1000 IOC rows in observable-service.
          </p>
          <div className="flex gap-2 mb-2">
            <input
              placeholder="IOC substring (ip, hash, domain…)"
              value={retroQ}
              onChange={(e) => setRetroQ(e.target.value)}
              className="w-full"
              style={{ maxWidth: 400 }}
            />
            <button type="button" onClick={() => void runRetro()}>
              Search
            </button>
          </div>
          <ul style={{ fontSize: 12, paddingLeft: 18 }}>
            {retroHits.map((h, i) => (
              <li key={i} className="mono mb-1">
                {JSON.stringify(h)}
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'mentions' && (
        <div className="card" style={{ padding: 14 }}>
          <p className="text-muted" style={{ fontSize: 12, marginTop: 0 }}>
            @mentions in case comments (match your JWT username). Also delivered via email / Slack when configured.
          </p>
          <button type="button" className="mb-3" onClick={() => void loadMyMentions()}>
            Refresh
          </button>
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Case</th>
                <th>From</th>
                <th>Excerpt</th>
              </tr>
            </thead>
            <tbody>
              {mentionItems.map((m) => (
                <tr key={m.id}>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {m.at || '—'}
                  </td>
                  <td>
                    <Link href={`/cases/${m.case_id}`} className="mono" style={{ fontSize: 11 }}>
                      {m.case_id.slice(0, 8)}…
                    </Link>
                  </td>
                  <td>{m.author}</td>
                  <td style={{ fontSize: 11 }}>{(m.excerpt || '').slice(0, 120)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!mentionItems.length ? <div className="empty-state">No mentions</div> : null}
        </div>
      )}

      {tab === 'watch' && (
        <div className="card" style={{ padding: 14 }}>
          <div className="flex gap-2 mb-3 flex-wrap">
            <input
              placeholder="Case UUID to watch"
              value={watchAdd}
              onChange={(e) => setWatchAdd(e.target.value)}
              style={{ minWidth: 260 }}
            />
            <button type="button" onClick={() => void addWatch()}>
              Add
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Case</th>
                <th>Since</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {watchItems.map((w) => (
                <tr key={w.case_id}>
                  <td>
                    <Link href={`/cases/${w.case_id}`} className="mono" style={{ fontSize: 12 }}>
                      {w.case_id}
                    </Link>
                  </td>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {w.created_at || '—'}
                  </td>
                  <td>
                    <button type="button" style={{ fontSize: 11 }} onClick={() => void removeWatch(w.case_id)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!watchItems.length ? <div className="empty-state">No watched cases</div> : null}
        </div>
      )}

      {tab === 'enrich' && (
        <div className="card" style={{ padding: 14 }}>
          <p className="text-muted" style={{ fontSize: 12, marginTop: 0 }}>
            Operational hints for pivoting to AbuseIPDB / OpenCTI (use existing alert intel modals for live lookups).
          </p>
          <div className="flex gap-2 mb-2">
            <input
              placeholder="Alert UUID"
              value={enrichAlert}
              onChange={(e) => setEnrichAlert(e.target.value)}
              style={{ minWidth: 280 }}
            />
            <button type="button" onClick={() => void loadEnrich()}>
              Load hints
            </button>
          </div>
          <ul style={{ fontSize: 12, paddingLeft: 18 }}>
            {enrichOut.map((h, i) => (
              <li key={i} className="mb-1">
                {JSON.stringify(h)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
