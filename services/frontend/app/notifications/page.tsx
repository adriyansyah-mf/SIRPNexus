'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useCallback, useEffect, useState } from 'react';

type ChannelRow = { configured?: boolean };

type DeliveryStatus = {
  ok?: boolean;
  error?: string;
  channels?: {
    email?: ChannelRow;
    slack?: ChannelRow;
    discord?: ChannelRow;
  };
};

function channelBadge(configured: boolean | undefined) {
  if (configured === true) return <span className="badge badge-resolved">configured</span>;
  if (configured === false) return <span className="badge badge-high">missing keys</span>;
  return <span className="text-muted">—</span>;
}

export default function NotificationsOpsPage() {
  const [status, setStatus] = useState<DeliveryStatus | null>(null);
  const [msg, setMsg] = useState('SIRP manual test ping from SOC console');
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState('');
  const [toastOk, setToastOk] = useState(true);
  const [err, setErr] = useState('');

  const loadStatus = useCallback(async () => {
    setErr('');
    const res = await fetch(`${CLIENT_API_PREFIX}/soc/notification-delivery-status`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) {
      setStatus(null);
      setErr(res.status === 401 ? 'Sign in required.' : `Could not load status (${res.status})`);
      return;
    }
    setStatus((await res.json()) as DeliveryStatus);
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const sendTest = async () => {
    setBusy(true);
    setToast('');
    try {
      const res = await fetch(`${CLIENT_API_PREFIX}/notifications/notifications/test`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setToastOk(true);
        setToast('Test dispatched — check email / Slack / Discord (if configured).');
      } else {
        setToastOk(false);
        setToast(typeof data.detail === 'string' ? data.detail : `Failed (${res.status})`);
      }
    } catch {
      setToastOk(false);
      setToast('Request failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-hd">
        <div>
          <h1>Notifications (operations)</h1>
          <div className="page-meta">
            Outbound alerts on <code className="mono">cases.updated</code> (Kafka) — verify channels before incidents
          </div>
        </div>
        <button type="button" onClick={() => void loadStatus()}>
          ↻ Refresh status
        </button>
      </div>

      {err ? (
        <div className="card mb-3" style={{ padding: 12, borderColor: 'var(--sev-high)' }}>
          {err}
        </div>
      ) : null}

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Configured channels</div>
        <p className="text-muted mb-3" style={{ fontSize: 12, marginTop: 0 }}>
          Shows whether required secret <strong>keys</strong> exist in secret-service (not values). Set them under{' '}
          <Link href="/admin">Admin</Link>.
        </p>
        {!status && !err ? <div className="empty-state">Loading…</div> : null}
        {status ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Email (SMTP)</td>
                <td>{channelBadge(status.channels?.email?.configured)}</td>
              </tr>
              <tr>
                <td>Slack webhook</td>
                <td>{channelBadge(status.channels?.slack?.configured)}</td>
              </tr>
              <tr>
                <td>Discord webhook</td>
                <td>{channelBadge(status.channels?.discord?.configured)}</td>
              </tr>
            </tbody>
          </table>
        ) : null}
        {status?.ok === false && status.error ? (
          <p className="text-muted mt-2" style={{ fontSize: 11 }}>
            Secret service: {status.error}
          </p>
        ) : null}
      </div>

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">Send test ping</div>
        <p className="text-muted mb-3" style={{ fontSize: 12, marginTop: 0 }}>
          Fires the same dispatch path as live case events (email + Slack + Discord where configured). Requires{' '}
          <strong>analyst</strong> role or above.
        </p>
        <label className="text-muted" style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>
          Message prefix
        </label>
        <input
          className="w-full mb-3"
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          disabled={busy}
        />
        <button type="button" className="btn-primary" disabled={busy} onClick={() => void sendTest()}>
          {busy ? 'Sending…' : 'Send test notification'}
        </button>
      </div>

      {toast ? <div className={`toast ${toastOk ? 'success' : 'error'}`}>{toast}</div> : null}
    </div>
  );
}
