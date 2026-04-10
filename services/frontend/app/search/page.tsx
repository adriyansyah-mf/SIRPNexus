import Link from 'next/link';
import { serverFetchGateway } from '../../lib/serverGateway';

type Hit = { kind: string; id: string; title: string; subtitle?: string };

type SearchResult = {
  query: string;
  cases: Hit[];
  alerts: Hit[];
  observables: Hit[];
};

async function runSearch(q: string): Promise<SearchResult | null> {
  const trimmed = q.trim();
  if (trimmed.length < 2) return null;
  const res = await serverFetchGateway(`/search?q=${encodeURIComponent(trimmed)}&limit_per=25`);
  if (!res.ok) return null;
  return res.json() as Promise<SearchResult>;
}

export default async function SearchPage({ searchParams }: { searchParams: { q?: string } }) {
  const q = searchParams.q || '';
  const data = await runSearch(q);

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Search</h1>
          <div className="page-meta">Cases, alerts, observables, comments & evidence names (server-side merge)</div>
        </div>
      </div>

      <form action="/search" method="get" className="card mb-4" style={{ padding: 16 }}>
        <label className="text-muted" style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>Query (min 2 characters)</label>
        <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
          <input
            name="q"
            defaultValue={q}
            placeholder="IP, domain, title, tag, alert id…"
            className="w-full"
            style={{ flex: 1, minWidth: 220 }}
          />
          <button type="submit" className="btn-primary">Search</button>
        </div>
      </form>

      {!q.trim() && <div className="empty-state">Enter a search query above.</div>}
      {q.trim() && q.trim().length < 2 && (
        <div className="empty-state">Use at least 2 characters.</div>
      )}
      {q.trim().length >= 2 && !data && (
        <div className="empty-state">Search failed or not authorized. Sign in and try again.</div>
      )}
      {data && (
        <div style={{ display: 'grid', gap: 24 }}>
          <section>
            <h2 style={{ fontSize: 15, marginBottom: 10 }}>Cases ({data.cases?.length || 0})</h2>
            <ul className="search-hit-list">
              {(data.cases || []).map((h) => (
                <li key={`c-${h.id}`}>
                  <Link href={`/cases/${h.id}`}>{h.title}</Link>
                  {h.subtitle ? <div className="text-muted" style={{ fontSize: 12 }}>{h.subtitle}</div> : null}
                </li>
              ))}
              {!data.cases?.length && <li className="text-muted">No matches</li>}
            </ul>
          </section>
          <section>
            <h2 style={{ fontSize: 15, marginBottom: 10 }}>Alerts ({data.alerts?.length || 0})</h2>
            <ul className="search-hit-list">
              {(data.alerts || []).map((h) => (
                <li key={`a-${h.id}`}>
                  <span className="mono" style={{ fontSize: 11 }}>{h.id.slice(0, 12)}…</span> — {h.title}
                  {h.subtitle ? <div className="text-muted" style={{ fontSize: 12 }}>{h.subtitle}</div> : null}
                </li>
              ))}
              {!data.alerts?.length && <li className="text-muted">No matches</li>}
            </ul>
          </section>
          <section>
            <h2 style={{ fontSize: 15, marginBottom: 10 }}>Observables ({data.observables?.length || 0})</h2>
            <ul className="search-hit-list">
              {(data.observables || []).map((h) => (
                <li key={`o-${h.id}`}>{h.title}</li>
              ))}
              {!data.observables?.length && <li className="text-muted">No matches</li>}
            </ul>
          </section>
        </div>
      )}
    </div>
  );
}
