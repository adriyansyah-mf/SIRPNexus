'use client';

import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import { useCallback, useEffect, useState } from 'react';

const INCIDENT_CATEGORIES = [
  '',
  'malware',
  'phishing',
  'credential_compromise',
  'ddos',
  'data_exfiltration',
  'insider_threat',
  'vulnerability_exploitation',
  'reconnaissance',
  'unauthorized_access',
  'policy_violation',
  'other',
];

type AuditEvent = { at?: string; actor?: string; action?: string; detail?: Record<string, unknown> };

export default function CaseSocTab({
  caseId,
  incidentCategory,
  legalHold,
  shiftHandoverNotes,
  auditEvents,
  onRefresh,
}: {
  caseId: string;
  incidentCategory?: string | null;
  legalHold?: boolean;
  shiftHandoverNotes?: string | null;
  auditEvents?: AuditEvent[];
  onRefresh: () => void;
}) {
  const [cat, setCat] = useState(incidentCategory || '');
  const [hold, setHold] = useState(!!legalHold);
  const [notes, setNotes] = useState(shiftHandoverNotes || '');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    setCat(incidentCategory || '');
    setHold(!!legalHold);
    setNotes(shiftHandoverNotes || '');
  }, [incidentCategory, legalHold, shiftHandoverNotes, caseId]);

  const saveMeta = useCallback(async () => {
    setSaving(true);
    setMsg('');
    try {
      const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${caseId}/soc-meta`, {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          incident_category: cat || null,
          legal_hold: hold,
          shift_handover_notes: notes,
          actor: 'soc_ui',
        }),
      });
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as { detail?: string };
        setMsg(typeof d.detail === 'string' ? d.detail : `Error ${res.status}`);
        return;
      }
      setMsg('Saved.');
      onRefresh();
    } finally {
      setSaving(false);
    }
  }, [caseId, cat, hold, notes, onRefresh]);

  const exportHandover = () => {
    const lines = [
      `# Shift handover — case ${caseId}`,
      `Incident category: ${cat || '—'}`,
      `Legal hold: ${hold ? 'yes' : 'no'}`,
      '',
      '## Notes',
      notes || '—',
      '',
      `Exported ${new Date().toISOString()}`,
    ];
    void navigator.clipboard.writeText(lines.join('\n')).then(
      () => setMsg('Handover copied to clipboard.'),
      () => setMsg('Copy failed.'),
    );
  };

  const events = [...(auditEvents || [])].reverse();

  return (
    <div>
      {msg ? (
        <div className="card mb-3" style={{ padding: 10, fontSize: 13 }}>{msg}</div>
      ) : null}

      <div className="card mb-4" style={{ padding: 14 }}>
        <div className="card-title mb-2">SOC classification &amp; hold</div>
        <p className="text-muted mb-3" style={{ fontSize: 12 }}>
          Taxonomy for reporting; <strong>legal hold</strong> blocks evidence deletion (HTTP 423) until cleared.
        </p>
        <div style={{ display: 'grid', gap: 12, maxWidth: 480 }}>
          <label className="text-muted" style={{ fontSize: 12 }}>
            Incident category
            <select className="w-full mt-1" value={cat} onChange={(e) => setCat(e.target.value)} style={{ marginTop: 4 }}>
              {INCIDENT_CATEGORIES.map((c) => (
                <option key={c || 'unset'} value={c}>{c || '(unset)'}</option>
              ))}
            </select>
          </label>
          <label style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" checked={hold} onChange={(e) => setHold(e.target.checked)} />
            Legal hold (protect evidence)
          </label>
          <label className="text-muted" style={{ fontSize: 12 }}>
            Shift handover notes
            <textarea
              className="w-full mt-1"
              rows={5}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="What the next shift must know…"
              style={{ marginTop: 4 }}
            />
          </label>
          <div className="flex gap-2 flex-wrap">
            <button type="button" className="btn-primary" disabled={saving} onClick={() => void saveMeta()}>
              {saving ? 'Saving…' : 'Save SOC fields'}
            </button>
            <button type="button" onClick={exportHandover}>
              Copy handover to clipboard
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 14 }}>
        <div className="card-title mb-2">Case audit trail (field &amp; actions)</div>
        <p className="text-muted mb-3" style={{ fontSize: 12 }}>
          Append-only events stored on the case (separate from gateway HTTP audit).
        </p>
        {!events.length ? <div className="empty-state">No audit entries yet.</div> : null}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 420, overflow: 'auto' }}>
          {events.map((e, i) => (
            <div
              key={`${e.at}-${i}`}
              style={{
                borderLeft: '3px solid var(--accent-amber)',
                paddingLeft: 10,
                fontSize: 12,
              }}
            >
              <div className="text-muted" style={{ fontSize: 11 }}>
                {e.at || '—'} · <span className="mono">{e.action}</span> · {e.actor || '—'}
              </div>
              {e.detail && Object.keys(e.detail).length > 0 ? (
                <pre className="mono text-muted" style={{ fontSize: 10, marginTop: 4, whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(e.detail)}
                </pre>
              ) : null}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
