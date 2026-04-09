const BASE = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

type Result = {
  alert_id?: string;
  type?: string;
  value?: string;
  status?: string;
  created_at?: string;
  result?: {
    risk?: { verdict?: string; score?: number };
    providers?: Record<string, unknown>;
  };
};

function verdictBadge(v?: string) {
  if (!v) return <span className="text-muted">—</span>;
  const map: Record<string, string> = { malicious: 'critical', suspicious: 'high', benign: 'low', unknown: 'info' };
  const cls = map[v.toLowerCase()] || 'info';
  return <span className={`badge badge-${cls}`}>{v}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'pending').toLowerCase();
  const cls = s === 'complete' ? 'closed' : s === 'error' ? 'escalated' : 'new';
  return <span className={`badge badge-${cls}`}>{st || 'pending'}</span>;
}

function typeBadge(t?: string) {
  const colors: Record<string, string> = { ip: 'info', domain: 'medium', hash: 'high', email: 'low', url: 'medium' };
  const cls = colors[t?.toLowerCase() || ''] || 'info';
  return <span className={`badge badge-${cls}`}>{t || '—'}</span>;
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
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}

async function getResults(): Promise<Result[]> {
  try {
    const res = await fetch(`${BASE}/analyzers/results`, { cache: 'no-store' });
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function ForensicsPage() {
  const results = await getResults();

  const malicious = results.filter((r) => r.result?.risk?.verdict?.toLowerCase() === 'malicious').length;
  const suspicious = results.filter((r) => r.result?.risk?.verdict?.toLowerCase() === 'suspicious').length;

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Forensics</h1>
          <div className="page-meta">{results.length} analyzer results · {malicious} malicious · {suspicious} suspicious</div>
        </div>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>IOC Value</th>
            <th>Type</th>
            <th>Verdict</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th className="hide-mobile">Alert ID</th>
            <th>Age</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, idx) => (
            <tr key={`${r.alert_id}-${r.value}-${idx}`}>
              <td className="mono truncate" style={{ maxWidth: 220 }}>{r.value || '—'}</td>
              <td>{typeBadge(r.type)}</td>
              <td>{verdictBadge(r.result?.risk?.verdict)}</td>
              <td>
                {r.result?.risk?.score != null
                  ? <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{r.result.risk.score}/100</span>
                  : <span className="text-muted">—</span>
                }
              </td>
              <td>{statusBadge(r.status)}</td>
              <td className="mono text-muted hide-mobile" style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {r.alert_id ? r.alert_id.slice(0, 16) + '…' : '—'}
              </td>
              <td className="text-muted">{relTime(r.created_at)}</td>
            </tr>
          ))}
          {!results.length && (
            <tr><td colSpan={7}><div className="empty-state">No analyzer results yet. Run analyzers on an alert to start enrichment.</div></td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
