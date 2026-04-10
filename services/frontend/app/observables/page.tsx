import { serverFetchGateway } from '../../lib/serverGateway';

type Observable = {
  id?: string;
  type?: string;
  value?: string;
  new?: boolean;
  tags?: string[];
  created_at?: string;
};

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

function typeBadge(t?: string) {
  const colors: Record<string, string> = {
    ip: 'info',
    domain: 'medium',
    hash: 'high',
    email: 'low',
    url: 'medium',
    hostname: 'medium',
    user: 'low',
    file: 'high',
    process: 'high',
    command: 'high',
    port: 'info',
    other: 'new',
  };
  const cls = colors[t?.toLowerCase() || ''] || 'info';
  return <span className={`badge badge-${cls}`}>{t || '—'}</span>;
}

async function getObservables(): Promise<Observable[]> {
  try {
    const res = await serverFetchGateway('/observables/observables');
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function ObservablesPage() {
  const obs = await getObservables();

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Observables</h1>
          <div className="page-meta">{obs.length} IOCs tracked</div>
        </div>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Value</th>
            <th>Type</th>
            <th>New</th>
            <th className="hide-mobile">Tags</th>
            <th>First seen</th>
          </tr>
        </thead>
        <tbody>
          {obs.map((o, idx) => (
            <tr key={`${o.id || o.value}-${idx}`}>
              <td className="mono" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {o.value || '—'}
              </td>
              <td>{typeBadge(o.type)}</td>
              <td>{o.new ? <span className="badge badge-new">yes</span> : <span className="text-muted">no</span>}</td>
              <td className="hide-mobile">
                <div className="tag-list">
                  {(o.tags || []).slice(0, 3).map((t) => <span className="tag" key={t}>{t}</span>)}
                </div>
              </td>
              <td className="text-muted">{relTime(o.created_at)}</td>
            </tr>
          ))}
          {!obs.length && (
            <tr><td colSpan={5}><div className="empty-state">No observables yet. They are auto-extracted from ingested alerts.</div></td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
