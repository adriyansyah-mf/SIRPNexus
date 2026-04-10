'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'sirp_hunting_saved_queries';

type LocalQuery = { id: string; label: string; q: string; at: string };
type ServerHunt = { id: string; label: string; query: string; created_at?: string | null };

function loadLocal(): LocalQuery[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const p = JSON.parse(raw) as LocalQuery[];
    return Array.isArray(p) ? p : [];
  } catch {
    return [];
  }
}

export default function HuntingPage() {
  const [localSaved, setLocalSaved] = useState<LocalQuery[]>([]);
  const [serverSaved, setServerSaved] = useState<ServerHunt[]>([]);
  const [label, setLabel] = useState('');
  const [q, setQ] = useState('');
  const [mounted, setMounted] = useState(false);
  const [token, setToken] = useState('');
  const [msg, setMsg] = useState('');

  const persistLocal = useCallback((list: LocalQuery[]) => {
    setLocalSaved(list);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  }, []);

  const loadServer = useCallback(async (t: string) => {
    if (!t) {
      setServerSaved([]);
      return;
    }
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/hunting/queries`, {
      cache: 'no-store',
      headers: { authorization: `Bearer ${t}` },
    });
    if (!res.ok) {
      setServerSaved([]);
      return;
    }
    const data = (await res.json()) as ServerHunt[];
    setServerSaved(Array.isArray(data) ? data : []);
  }, []);

  useEffect(() => {
    setMounted(true);
    setLocalSaved(loadLocal());
    const t = localStorage.getItem('sirp_token') || '';
    setToken(t);
    void loadServer(t);
  }, [loadServer]);

  const saveLocal = () => {
    const trimmed = q.trim();
    if (trimmed.length < 2) return;
    const item: LocalQuery = {
      id: `local-${Date.now()}`,
      label: label.trim() || trimmed.slice(0, 40),
      q: trimmed,
      at: new Date().toISOString(),
    };
    persistLocal([item, ...localSaved].slice(0, 30));
    setLabel('');
    setMsg('Saved to this browser.');
  };

  const saveServer = async () => {
    const trimmed = q.trim();
    if (trimmed.length < 2 || !token) return;
    setMsg('');
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/hunting/queries`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ label: label.trim() || trimmed.slice(0, 80), query: trimmed }),
    });
    const data = (await res.json().catch(() => ({}))) as { detail?: string };
    if (!res.ok) {
      setMsg(typeof data.detail === 'string' ? data.detail : `Save failed (${res.status})`);
      return;
    }
    setLabel('');
    setMsg('Saved to server (per user).');
    void loadServer(token);
  };

  const removeLocal = (id: string) => {
    persistLocal(localSaved.filter((x) => x.id !== id));
  };

  const removeServer = async (id: string) => {
    if (!token) return;
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/hunting/queries/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
    });
    if (res.ok) void loadServer(token);
    else setMsg('Could not delete server hunt');
  };

  if (!mounted) {
    return <div className="empty-state">Loading…</div>;
  }

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Threat hunting</h1>
          <div className="page-meta">Server-side saved queries + browser-only backup · links to global search</div>
        </div>
      </div>

      {msg ? <div className="card mb-3" style={{ padding: 10, fontSize: 13 }}>{msg}</div> : null}

      <div className="card mb-4" style={{ padding: 16 }}>
        <div className="card-title mb-2">New hunt / pivot</div>
        <p className="text-muted mb-3" style={{ fontSize: 13 }}>
          Minimum 2 characters. Same backend as <Link href="/search">Search</Link> (cases, alerts, observables).
        </p>
        <div className="flex gap-2 flex-wrap" style={{ alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label className="text-muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Label (optional)</label>
            <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. C2 subnet" className="w-full" />
          </div>
          <div style={{ flex: 2, minWidth: 220 }}>
            <label className="text-muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Query</label>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP · hash · MITRE tag · hostname" className="w-full" />
          </div>
          <Link
            href={q.trim().length >= 2 ? `/search?q=${encodeURIComponent(q.trim())}` : '#'}
            className="btn-primary"
            style={{ opacity: q.trim().length >= 2 ? 1 : 0.5, pointerEvents: q.trim().length >= 2 ? 'auto' : 'none' }}
          >
            Run search
          </Link>
          <button type="button" onClick={saveLocal}>Save (browser)</button>
          <button type="button" className="btn-primary" onClick={() => void saveServer()} disabled={!token || q.trim().length < 2}>
            Save (server)
          </button>
        </div>
        {!token ? (
          <p className="text-muted mt-2" style={{ fontSize: 12 }}>Sign in to save hunts to the platform database (shared per username).</p>
        ) : null}
      </div>

      <div className="card mb-4" style={{ padding: 16 }}>
        <div className="card-title mb-2">Saved on server ({serverSaved.length})</div>
        {!token ? <div className="empty-state">Sign in to see server hunts.</div> : null}
        {token && !serverSaved.length ? <div className="empty-state">No server hunts yet.</div> : null}
        <ul className="search-hit-list">
          {serverSaved.map((s) => (
            <li key={s.id} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              <span className="badge badge-info" style={{ fontSize: 10 }}>server</span>
              <strong>{s.label}</strong>
              <span className="mono text-muted" style={{ fontSize: 12 }}>{s.query}</span>
              <Link href={`/search?q=${encodeURIComponent(s.query)}`} className="btn-primary" style={{ fontSize: 11, padding: '4px 10px' }}>Run</Link>
              <button type="button" style={{ fontSize: 11 }} onClick={() => void removeServer(s.id)}>Remove</button>
            </li>
          ))}
        </ul>
      </div>

      <div className="card" style={{ padding: 16 }}>
        <div className="card-title mb-2">This browser only ({localSaved.length})</div>
        {!localSaved.length ? <div className="empty-state">No local hunts.</div> : null}
        <ul className="search-hit-list">
          {localSaved.map((s) => (
            <li key={s.id} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              <span className="badge badge-medium" style={{ fontSize: 10 }}>local</span>
              <strong>{s.label}</strong>
              <span className="mono text-muted" style={{ fontSize: 12 }}>{s.q}</span>
              <Link href={`/search?q=${encodeURIComponent(s.q)}`} className="btn-primary" style={{ fontSize: 11, padding: '4px 10px' }}>Run</Link>
              <button type="button" style={{ fontSize: 11 }} onClick={() => removeLocal(s.id)}>Remove</button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
