import Link from 'next/link';
import { serverFetchGateway } from '../../lib/serverGateway';

type AuditRow = {
  id: number;
  at: string | null;
  actor: string;
  resource_type: string | null;
  resource_id: string | null;
  method: string;
  path: string;
  status_code: number;
  detail: unknown;
};

export default async function AuditPage({
  searchParams,
}: {
  searchParams: { actor?: string; resource_type?: string };
}) {
  const params = new URLSearchParams();
  params.set('limit', '200');
  const actor = (searchParams.actor || '').trim();
  const resourceType = (searchParams.resource_type || '').trim();
  if (actor) params.set('actor', actor);
  if (resourceType) params.set('resource_type', resourceType);

  const res = await serverFetchGateway(`/audit/events?${params.toString()}`);
  const rows: AuditRow[] = res.ok ? await res.json() : [];

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Audit log</h1>
          <div className="page-meta">Append-only mutations (gateway proxy + admin user actions)</div>
        </div>
      </div>

      <form action="/audit" method="get" className="card mb-4" style={{ padding: 16 }}>
        <div className="flex gap-2" style={{ flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <label className="text-muted" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>Actor</label>
            <input name="actor" defaultValue={actor} placeholder="username / sub" style={{ width: '100%' }} />
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <label className="text-muted" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>Resource type</label>
            <input name="resource_type" defaultValue={resourceType} placeholder="case, user, …" style={{ width: '100%' }} />
          </div>
          <button type="submit" className="btn-primary">Apply</button>
          {(actor || resourceType) ? (
            <Link href="/audit" style={{ fontSize: 13 }}>Clear</Link>
          ) : null}
        </div>
      </form>

      {!res.ok && (
        <div className="card" style={{ padding: 16, borderColor: 'var(--sev-high)' }}>
          Could not load audit log (sign in, or insufficient role).
        </div>
      )}

      {res.ok && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Time (UTC)</th>
              <th>Actor</th>
              <th>Method</th>
              <th className="hide-mobile">Path</th>
              <th>Type</th>
              <th>ID</th>
              <th>HTTP</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="mono text-muted" style={{ fontSize: 11 }}>{r.at || '—'}</td>
                <td>{r.actor}</td>
                <td><span className="badge badge-info">{r.method}</span></td>
                <td className="mono hide-mobile" style={{ fontSize: 10 }}>{r.path}</td>
                <td className="text-muted" style={{ fontSize: 12 }}>{r.resource_type || '—'}</td>
                <td className="mono" style={{ fontSize: 10 }}>{r.resource_id ? `${r.resource_id.slice(0, 8)}…` : '—'}</td>
                <td>{r.status_code}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr><td colSpan={7}><div className="empty-state">No audit entries match the filters.</div></td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
