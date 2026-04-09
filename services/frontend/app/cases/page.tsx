const BASE = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

type Case = {
  id: string;
  title?: string;
  status?: string;
  severity?: string;
  owner?: string;
  assigned_to?: string;
  created_at?: string;
  tags?: string[];
};

function statusBadge(st?: string) {
  const s = (st || 'open').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'open'}</span>;
}

function sevBadge(sev?: string) {
  if (!sev) return null;
  const s = sev.toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
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

async function getCases(): Promise<Case[]> {
  try {
    const res = await fetch(`${BASE}/cases/cases`, { cache: 'no-store' });
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function CasesPage() {
  const cases = await getCases();
  const open = cases.filter((c) => !['resolved', 'closed'].includes(c.status?.toLowerCase() || '')).length;

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Cases</h1>
          <div className="page-meta">{open} open · {cases.length} total</div>
        </div>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Status</th>
            <th>Severity</th>
            <th className="hide-mobile">Assigned</th>
            <th className="hide-mobile">Owner</th>
            <th className="hide-mobile">Tags</th>
            <th>Age</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((c) => (
            <tr key={c.id}>
              <td>
                <a href={`/cases/${c.id}`} style={{ color: 'var(--accent-blue)', fontWeight: 500 }}>
                  {c.title || 'Untitled Case'}
                </a>
                <div className="mono text-muted mt-1">{c.id.slice(0, 16)}…</div>
              </td>
              <td>{statusBadge(c.status)}</td>
              <td>{sevBadge(c.severity)}</td>
              <td className="text-muted hide-mobile">{c.assigned_to || '—'}</td>
              <td className="text-muted hide-mobile">{c.owner || '—'}</td>
              <td className="hide-mobile">
                <div className="tag-list">
                  {(c.tags || []).slice(0, 3).map((t) => <span className="tag" key={t}>{t}</span>)}
                </div>
              </td>
              <td className="text-muted">{relTime(c.created_at)}</td>
            </tr>
          ))}
          {!cases.length && (
            <tr><td colSpan={7}><div className="empty-state">No cases yet. Escalate an alert to create one.</div></td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
