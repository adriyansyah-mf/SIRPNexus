'use client';

import Link from 'next/link';
import { CLIENT_API_PREFIX } from '../../../lib/clientApi';
import { openctiKnowledgeSearchUrl } from '../../../lib/openctiLinks';
import { useEffect, useRef, useState, type CSSProperties } from 'react';
import CaseInvestigation from './CaseInvestigation';
import CaseSocTab from './CaseSocTab';

type CaseEvidence = {
  id: string;
  filename?: string;
  size?: number;
  content_type?: string;
  uploaded_at?: string;
  uploaded_by?: string | null;
};

type Case = {
  id: string;
  title?: string;
  description?: string;
  status?: string;
  severity?: string;
  owner?: string;
  assigned_to?: string | null;
  assigned_by?: string | null;
  assigned_at?: string | null;
  created_at?: string;
  updated_at?: string;
  alert_id?: string;
  tags?: string[];
  sla?: { response_due: string; resolution_due: string; breached: boolean };
  timeline?: { event: string; at: string }[];
  comments?: { id: string; author: string; text: string; at: string; edited?: boolean }[];
  tasks?: { id: string; title: string; status: string; assigned_to?: string }[];
  observables?: { type: string; value: string }[];
  evidence?: CaseEvidence[];
  linked_case_ids?: string[];
  audit_events?: { at?: string; actor?: string; action?: string; detail?: Record<string, unknown> }[];
  incident_category?: string | null;
  legal_hold?: boolean;
  shift_handover_notes?: string | null;
};

type SourceAlertPreview = {
  id: string;
  title?: string;
  description?: string;
  summary?: string;
  severity?: string;
  source?: string;
  status?: string;
  created_at?: string;
  location?: string;
  agent?: { id?: string; name?: string; ip?: string };
  rule_ref?: { id?: string | number; level?: number; description?: string; groups?: string[] | string };
};

type OpenctiMatch = {
  id?: string;
  standard_id?: string;
  entity_type?: string;
  observable_value?: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
};

type IntelSource = 'opencti' | 'abuseipdb';

type OpenctiLookupResult = {
  search: string;
  matches: OpenctiMatch[];
  page_info?: { globalCount?: number };
  graphql_errors?: unknown;
  auth_hint?: string;
};

type AbuseipdbLookupResult = {
  source?: string;
  ip?: string;
  data?: Record<string, unknown>;
  api_errors?: unknown;
};

type IntelLookupModal = {
  source: IntelSource;
  iocType: string;
  iocValue: string;
  loading: boolean;
  error: string | null;
  opencti: OpenctiLookupResult | null;
  abuseipdb: AbuseipdbLookupResult | null;
};

function observableSupportsAbuseIpdb(o: { type: string; value: string }): boolean {
  if (o.type.toLowerCase() === 'ip') return true;
  const v = o.value.trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return true;
  if (v.includes(':') && /^[0-9a-f:.]+$/i.test(v)) return true;
  return false;
}

function sevBadge(sev?: string) {
  const s = (sev || 'medium').toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function statusBadge(st?: string) {
  const s = (st || 'open').toLowerCase().replace(' ', '-');
  return <span className={`badge badge-${s}`}>{st || 'open'}</span>;
}

function relTime(ts?: string) {
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

const OPENCTI_URL = (process.env.NEXT_PUBLIC_OPENCTI_URL || '').trim();

const MITRE_TAG_RE = /^T\d{4}(?:\.\d{3})?$/i;

function mitreTechniqueUrl(tag: string): string {
  const t = tag.trim().toUpperCase();
  const m = t.match(/^T(\d{4})(?:\.(\d{3}))?$/);
  if (!m) return 'https://attack.mitre.org/';
  const base = `https://attack.mitre.org/techniques/T${m[1]}`;
  return m[2] ? `${base}/${m[2]}/` : `${base}/`;
}

function partitionMitreTags(tags: string[]): { mitre: string[]; other: string[] } {
  const mitre: string[] = [];
  const other: string[] = [];
  for (const t of tags) {
    if (MITRE_TAG_RE.test(t.trim())) mitre.push(t.trim());
    else other.push(t);
  }
  return { mitre, other };
}

function parseDescriptionHints(text: string): { label: string; value: string }[] {
  const patterns: [string, RegExp][] = [
    ['Rule ID', /^Rule ID:\s*(.+)$/im],
    ['Agent / endpoint', /^Agent \/ endpoint:\s*(.+)$/im],
    ['Source IP', /^Source IP:\s*(.+)$/im],
    ['Destination IP', /^Destination IP:\s*(.+)$/im],
    ['URL', /^URL:\s*(.+)$/im],
    ['User', /^User:\s*(.+)$/im],
    ['MD5', /^MD5:\s*(.+)$/im],
    ['SHA256', /^SHA256:\s*(.+)$/im],
    ['Hostname', /^Hostname:\s*(.+)$/im],
  ];
  const out: { label: string; value: string }[] = [];
  for (const [label, re] of patterns) {
    const m = text.match(re);
    if (m?.[1]) out.push({ label, value: m[1].trim() });
  }
  return out;
}

function formatUtc(ts?: string): string {
  if (!ts) return '—';
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) return ts;
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

function sourceAlertAgentLine(a?: SourceAlertPreview['agent']): string {
  if (!a) return '';
  const parts: string[] = [];
  if (a.name) parts.push(String(a.name));
  if (a.ip) parts.push(String(a.ip));
  if (a.id !== undefined && a.id !== '') parts.push(`id ${a.id}`);
  return parts.join(' · ');
}

function openTaskCount(tasks: Case['tasks']): number {
  return (tasks || []).filter((t) => String(t.status || '').toLowerCase() !== 'done').length;
}

function evidenceTotalBytes(ev: CaseEvidence[] | undefined): number {
  return (ev || []).reduce((s, e) => s + (typeof e.size === 'number' ? e.size : 0), 0);
}

function OverviewHintValue({
  label,
  value,
  onOpenObservables,
}: {
  label: string;
  value: string;
  onOpenObservables: () => void;
}) {
  const isUrl = label === 'URL' || /^https?:\/\//i.test(value);
  const v = value.trim();
  if (isUrl) {
    const href = v.startsWith('http') ? v : `https://${v}`;
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>
        {value}
      </a>
    );
  }
  if (label === 'Source IP' || label === 'Destination IP') {
    return (
      <button
        type="button"
        onClick={onOpenObservables}
        className="mono"
        style={{
          fontSize: 12,
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 4,
          padding: '2px 8px',
          cursor: 'pointer',
          color: 'var(--accent-blue)',
        }}
        title="Open Observables tab"
      >
        {value}
      </button>
    );
  }
  return <span className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{value}</span>;
}

function formatBytes(n?: number): string {
  if (n == null || Number.isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function jwtPreferredUsername(token: string): string {
  try {
    const p = token.split('.')[1];
    const json = atob(p.replace(/-/g, '+').replace(/_/g, '/'));
    const o = JSON.parse(json) as { preferred_username?: string; sub?: string };
    return o.preferred_username || o.sub || 'user';
  } catch {
    return 'user';
  }
}

export default function CaseDetail({ params }: { params: { id: string } }) {
  const [c, setC] = useState<Case | null>(null);
  const [toast, setToast] = useState('');
  const [toastOk, setToastOk] = useState(true);
  const [commentText, setCommentText] = useState('');
  const [taskTitle, setTaskTitle] = useState('');
  const [taskAssignee, setTaskAssignee] = useState('');
  const [tab, setTab] = useState<
    'overview' | 'investigation' | 'soc' | 'evidence' | 'tasks' | 'comments' | 'timeline' | 'observables'
  >('overview');
  const [evidenceUploading, setEvidenceUploading] = useState(false);
  const [intelSource, setIntelSource] = useState<IntelSource>('opencti');
  const [intelModal, setIntelModal] = useState<IntelLookupModal | null>(null);
  const [sourceAlert, setSourceAlert] = useState<SourceAlertPreview | null>(null);
  const [sourceAlertErr, setSourceAlertErr] = useState('');
  const toastRef = useRef<ReturnType<typeof setTimeout>>();

  const token = typeof window !== 'undefined' ? (localStorage.getItem('sirp_token') || '') : '';
  const authHdr = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  const notify = (msg: string, ok = true) => {
    setToast(msg);
    setToastOk(ok);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 4000);
  };

  const load = async () => {
    const h = token ? { authorization: `Bearer ${token}` } : {};
    const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}`, { cache: 'no-store', headers: h });
    if (!res.ok) return;
    const data = await res.json();
    setC(data);
  };

  const exportCaseJson = async () => {
    if (!token) {
      notify('Sign in to export', false);
      return;
    }
    try {
      const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/export`, {
        cache: 'no-store',
        headers: { authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        notify(`Export failed (${res.status})`, false);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `case-${params.id}-export.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      notify('Export downloaded');
    } catch {
      notify('Export failed', false);
    }
  };

  useEffect(() => {
    void load();
  }, [params.id, token]);

  useEffect(() => {
    if (!c?.alert_id || !token) {
      setSourceAlert(null);
      setSourceAlertErr('');
      return;
    }
    let cancelled = false;
    setSourceAlert(null);
    setSourceAlertErr('');
    (async () => {
      try {
        const res = await fetch(`${CLIENT_API_PREFIX}/alerts/alerts/${c.alert_id}`, {
          cache: 'no-store',
          headers: { authorization: `Bearer ${token}` },
        });
        if (cancelled) return;
        if (!res.ok) {
          setSourceAlertErr(
            res.status === 404 ? 'Alert not found (may have been purged).' : `Could not load alert (${res.status}).`,
          );
          return;
        }
        const data = (await res.json()) as SourceAlertPreview;
        if (!cancelled) setSourceAlert(data);
      } catch {
        if (!cancelled) setSourceAlertErr('Could not load source alert.');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [c?.alert_id, c?.id, token]);

  const runIntelLookup = async (o: { type: string; value: string }, source: IntelSource) => {
    setIntelModal({
      source,
      iocType: o.type,
      iocValue: o.value,
      loading: true,
      error: null,
      opencti: null,
      abuseipdb: null,
    });
    if (source === 'abuseipdb') {
      const res = await fetch(`${CLIENT_API_PREFIX}/alerts/abuseipdb/lookup`, {
        method: 'POST',
        headers: authHdr,
        body: JSON.stringify({ value: o.value, maxAgeInDays: 90 }),
      });
      const data = (await res.json().catch(() => ({}))) as AbuseipdbLookupResult & { detail?: string };
      if (!res.ok) {
        const msg = typeof data.detail === 'string' ? data.detail : `AbuseIPDB lookup failed (${res.status})`;
        setIntelModal((m) => (m ? { ...m, loading: false, error: msg } : null));
        return;
      }
      setIntelModal((m) =>
        m
          ? {
              ...m,
              loading: false,
              error: null,
              abuseipdb: {
                source: data.source,
                ip: data.ip,
                data: data.data,
                api_errors: data.api_errors,
              },
            }
          : null,
      );
      return;
    }
    const res = await fetch(`${CLIENT_API_PREFIX}/alerts/opencti/lookup`, {
      method: 'POST',
      headers: authHdr,
      body: JSON.stringify({ value: o.value, type: o.type, first: 25 }),
    });
    const data = (await res.json().catch(() => ({}))) as {
      detail?: string;
      search?: string;
      matches?: OpenctiMatch[];
      page_info?: { globalCount?: number };
      graphql_errors?: unknown;
      auth_hint?: string;
    };
    if (!res.ok) {
      const msg = typeof data.detail === 'string' ? data.detail : `OpenCTI lookup failed (${res.status})`;
      setIntelModal((m) => (m ? { ...m, loading: false, error: msg } : null));
      return;
    }
    setIntelModal((m) =>
      m
        ? {
            ...m,
            loading: false,
            error: null,
            opencti: {
              search: data.search || o.value,
              matches: Array.isArray(data.matches) ? data.matches : [],
              page_info: data.page_info,
              graphql_errors: data.graphql_errors,
              auth_hint: data.auth_hint,
            },
          }
        : null,
    );
  };

  const setStatus = async (status: string) => {
    const actor = token ? 'admin' : 'ui';
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/status`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ status, actor }),
    });
    notify(`Status → ${status}`);
    load();
  };

  const addComment = async () => {
    if (!commentText.trim()) return;
    const author = token ? 'analyst' : 'anonymous';
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/comments`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ author, text: commentText }),
    });
    setCommentText('');
    notify('Comment added');
    load();
  };

  const deleteComment = async (cid: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/comments/${cid}`, { method: 'DELETE', headers: authHdr });
    notify('Comment deleted');
    load();
  };

  const addTask = async () => {
    if (!taskTitle.trim()) return;
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks`, {
      method: 'POST', headers: authHdr,
      body: JSON.stringify({ title: taskTitle, assigned_to: taskAssignee }),
    });
    setTaskTitle(''); setTaskAssignee('');
    notify('Task added');
    load();
  };

  const updateTaskStatus = async (tid: string, status: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks/${tid}`, {
      method: 'PUT', headers: authHdr,
      body: JSON.stringify({ status }),
    });
    notify(`Task → ${status}`);
    load();
  };

  const deleteTask = async (tid: string) => {
    await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/tasks/${tid}`, { method: 'DELETE', headers: authHdr });
    notify('Task deleted');
    load();
  };

  const uploadEvidence = async (files: FileList | null) => {
    if (!files?.length) return;
    const f = files[0];
    setEvidenceUploading(true);
    const fd = new FormData();
    fd.append('file', f);
    fd.append('uploaded_by', token ? jwtPreferredUsername(token) : 'anonymous');
    try {
      const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/evidence`, {
        method: 'POST',
        headers: token ? { authorization: `Bearer ${token}` } : {},
        body: fd,
      });
      const data = (await res.json().catch(() => ({}))) as { detail?: string };
      if (!res.ok) {
        notify(typeof data.detail === 'string' ? data.detail : `Upload failed (${res.status})`, false);
        return;
      }
      notify(`Uploaded: ${f.name}`);
      load();
    } finally {
      setEvidenceUploading(false);
    }
  };

  const downloadEvidence = async (eid: string, filename: string) => {
    const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/evidence/${eid}/file`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      notify(`Download failed (${res.status})`, false);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'evidence';
    a.click();
    URL.revokeObjectURL(url);
  };

  const deleteEvidence = async (eid: string) => {
    if (!window.confirm('Remove this evidence file?')) return;
    const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases/${params.id}/evidence/${eid}`, {
      method: 'DELETE',
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    if (res.status === 423) {
      const d = (await res.json().catch(() => ({}))) as { detail?: string };
      notify(typeof d.detail === 'string' ? d.detail : 'Legal hold blocks deletion', false);
      return;
    }
    if (!res.ok) {
      notify(`Remove failed (${res.status})`, false);
      return;
    }
    notify('Evidence removed');
    load();
  };

  const tabStyle = (t: typeof tab): CSSProperties => ({
    padding: '8px 14px', cursor: 'pointer', fontSize: 13, fontWeight: tab === t ? 600 : 400,
    color: tab === t ? 'var(--text-primary)' : 'var(--text-secondary)',
    borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
    background: 'none', border: 'none', borderRadius: 0,
  });

  if (!c) return <div className="empty-state">Loading case…</div>;

  return (
    <div>
      {/* Header */}
      <div className="page-hd">
        <div>
          <h1 style={{ marginBottom: 4 }}>{c.title}</h1>
          <div className="flex gap-2 items-center">
            {sevBadge(c.severity)}{statusBadge(c.status)}
            {c.assigned_to && <span className="text-muted" style={{ fontSize: 12 }}>Assigned: {c.assigned_to}</span>}
            <span className="text-muted" style={{ fontSize: 12 }}>Created {relTime(c.created_at)}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <select
            value={c.status}
            onChange={(e) => setStatus(e.target.value)}
            style={{ fontSize: 12 }}
          >
            <option value="open">open</option>
            <option value="in-progress">in-progress</option>
            <option value="resolved">resolved</option>
            <option value="closed">closed</option>
          </select>
          <button type="button" onClick={() => void exportCaseJson()} style={{ fontSize: 12 }}>
            Export JSON
          </button>
          <button onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', marginBottom: 16, flexWrap: 'wrap' }}>
        {(['overview', 'investigation', 'soc', 'evidence', 'tasks', 'comments', 'timeline', 'observables'] as const).map((t) => (
          <button key={t} style={tabStyle(t)} onClick={() => setTab(t)}>
            {t === 'evidence' ? 'Evidence' : t === 'investigation' ? 'Investigation' : t === 'soc' ? 'SOC' : t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'tasks' && c.tasks?.length ? ` (${c.tasks.length})` : ''}
            {t === 'comments' && c.comments?.length ? ` (${c.comments.length})` : ''}
            {t === 'evidence' && c.evidence?.length ? ` (${c.evidence.length})` : ''}
          </button>
        ))}
      </div>

      {/* Overview */}
      {tab === 'overview' && (() => {
        const { mitre: mitreTags, other: otherTags } = partitionMitreTags(c.tags || []);
        const descHints = parseDescriptionHints(c.description || '');
        const lastTimeline = c.timeline?.length ? c.timeline[c.timeline.length - 1] : null;
        const obsCount = c.observables?.length ?? 0;
        const evCount = c.evidence?.length ?? 0;
        const evBytes = evidenceTotalBytes(c.evidence);
        const taskOpen = openTaskCount(c.tasks);
        const taskTotal = c.tasks?.length ?? 0;
        const commentCount = c.comments?.length ?? 0;

        const copyText = (label: string, text: string) => {
          void navigator.clipboard.writeText(text).then(
            () => notify(`${label} copied`),
            () => notify('Copy failed', false),
          );
        };

        const slaDueCell = (due?: string) =>
          !due ? (
            '—'
          ) : (
            <span>
              <span title={formatUtc(due)}>{relTime(due)}</span>
              <span className="text-muted" style={{ fontSize: 11, marginLeft: 8 }}>{formatUtc(due)}</span>
            </span>
          );

        return (
          <div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 20 }}>
              {(
                [
                  ['Observables', obsCount, 'observables' as const],
                  ['Evidence', `${evCount} · ${formatBytes(evBytes)}`, 'evidence' as const],
                  ['Tasks', `${taskOpen} open / ${taskTotal}`, 'tasks' as const],
                  ['Comments', commentCount, 'comments' as const],
                ] as const
              ).map(([label, val, target]) => (
                <button
                  key={label}
                  type="button"
                  className="card"
                  style={{
                    padding: '12px 16px',
                    cursor: 'pointer',
                    textAlign: 'left',
                    minWidth: 130,
                    border: '1px solid var(--border-subtle)',
                  }}
                  onClick={() => setTab(target)}
                >
                  <div className="text-muted" style={{ fontSize: 11 }}>{label}</div>
                  <div style={{ fontSize: 17, fontWeight: 600 }}>{val}</div>
                </button>
              ))}
            </div>

            {c.alert_id ? (
              <div className="card mb-4" style={{ padding: 14 }}>
                <div className="card-title mb-2">Source alert</div>
                {sourceAlertErr ? (
                  <div style={{ fontSize: 13, color: 'var(--sev-high)' }}>{sourceAlertErr}</div>
                ) : null}
                {!sourceAlert && !sourceAlertErr ? (
                  <div className="text-muted" style={{ fontSize: 13 }}>Loading alert…</div>
                ) : null}
                {sourceAlert ? (
                  <div style={{ fontSize: 13, display: 'grid', gap: 8 }}>
                    <div className="flex gap-2 flex-wrap items-center">
                      {sevBadge(sourceAlert.severity)}
                      {statusBadge(sourceAlert.status)}
                      {sourceAlert.source ? <span className="badge badge-info">{sourceAlert.source}</span> : null}
                      <span className="text-muted" style={{ fontSize: 12 }}>ingested {relTime(sourceAlert.created_at)}</span>
                    </div>
                    <div style={{ fontWeight: 600 }}>{sourceAlert.title || '—'}</div>
                    {sourceAlert.rule_ref?.id !== undefined && sourceAlert.rule_ref.id !== '' ? (
                      <div className="text-muted" style={{ fontSize: 12 }}>
                        Rule <span className="mono">{String(sourceAlert.rule_ref.id)}</span>
                        {sourceAlert.rule_ref.level != null ? ` · level ${sourceAlert.rule_ref.level}` : ''}
                        {sourceAlert.rule_ref.description ? ` · ${sourceAlert.rule_ref.description}` : ''}
                      </div>
                    ) : null}
                    {sourceAlertAgentLine(sourceAlert.agent) ? (
                      <div className="text-muted" style={{ fontSize: 12 }}>
                        Agent: <span className="mono">{sourceAlertAgentLine(sourceAlert.agent)}</span>
                      </div>
                    ) : null}
                    {sourceAlert.location ? (
                      <div className="text-muted mono" style={{ fontSize: 12 }}>Location: {sourceAlert.location}</div>
                    ) : null}
                    {(sourceAlert.summary || sourceAlert.description) ? (
                      <div style={{ whiteSpace: 'pre-wrap', fontSize: 12, color: 'var(--text-secondary)' }}>
                        {(sourceAlert.summary || sourceAlert.description || '').slice(0, 800)}
                        {(sourceAlert.summary || sourceAlert.description || '').length > 800 ? '…' : ''}
                      </div>
                    ) : null}
                    <div className="flex gap-2 flex-wrap">
                      <Link href="/alerts" style={{ fontSize: 12 }}>Open Alerts list</Link>
                      <button type="button" style={{ fontSize: 12 }} onClick={() => copyText('Alert ID', c.alert_id!)}>
                        Copy alert ID
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}

            {descHints.length > 0 ? (
              <div className="card mb-4" style={{ padding: 14 }}>
                <div className="card-title mb-2">Parsed from description</div>
                <p className="text-muted mb-3" style={{ fontSize: 12 }}>
                  Key-value lines detected in the case description (IPs link to the Observables tab).
                </p>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <tbody>
                    {descHints.map((h) => (
                      <tr key={`${h.label}:${h.value}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '6px 12px 6px 0', width: 140, color: 'var(--text-muted)', verticalAlign: 'top' }}>
                          {h.label}
                        </td>
                        <td style={{ padding: '6px 0' }}>
                          <OverviewHintValue
                            label={h.label}
                            value={h.value}
                            onOpenObservables={() => setTab('observables')}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <tbody>
                {[
                  [
                    'Case ID',
                    <div className="flex gap-2 items-start" style={{ flexWrap: 'wrap' }}>
                      <span className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{c.id}</span>
                      <button type="button" style={{ fontSize: 11 }} onClick={() => copyText('Case ID', c.id)}>
                        Copy
                      </button>
                    </div>,
                  ],
                  ['Origin', c.alert_id ? 'Escalated from alert' : 'Created manually'],
                  ['Severity', sevBadge(c.severity)],
                  ['Status', statusBadge(c.status)],
                  ['Owner', c.owner || '—'],
                  [
                    'Assigned to',
                    c.assigned_to ? (
                      <div>
                        <div>{c.assigned_to}</div>
                        {(c.assigned_by || c.assigned_at) ? (
                          <div className="text-muted" style={{ fontSize: 11, marginTop: 4 }}>
                            {c.assigned_by ? <>By <span className="mono">{c.assigned_by}</span></> : null}
                            {c.assigned_at ? (
                              <>
                                {c.assigned_by ? ' · ' : null}
                                {formatUtc(c.assigned_at)} <span className="text-muted">({relTime(c.assigned_at)})</span>
                              </>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    ) : (
                      '—'
                    ),
                  ],
                  [
                    'MITRE techniques',
                    mitreTags.length ? (
                      <span className="flex gap-2" style={{ flexWrap: 'wrap' }}>
                        {mitreTags.map((t) => (
                          <a
                            key={t}
                            href={mitreTechniqueUrl(t)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="tag"
                            style={{ textDecoration: 'none' }}
                            title="MITRE ATT&CK"
                          >
                            {t} ↗
                          </a>
                        ))}
                      </span>
                    ) : (
                      '—'
                    ),
                  ],
                  [
                    'Tags',
                    otherTags.length ? (
                      <span className="flex gap-2" style={{ flexWrap: 'wrap' }}>
                        {otherTags.map((t) => (
                          <span key={t} className="tag">{t}</span>
                        ))}
                      </span>
                    ) : (
                      '—'
                    ),
                  ],
                  [
                    'Incident category',
                    <span>
                      {c.incident_category ? <span className="badge badge-info">{c.incident_category}</span> : '—'}
                      <span className="text-muted" style={{ fontSize: 11, marginLeft: 8 }}>Edit in <strong>SOC</strong> tab</span>
                    </span>,
                  ],
                  [
                    'Legal hold',
                    c.legal_hold ? (
                      <span><span className="badge badge-high">Active</span> — evidence deletion blocked</span>
                    ) : (
                      '—'
                    ),
                  ],
                  [
                    'Linked cases',
                    <div>
                      {(c.linked_case_ids || []).length ? (
                        <span className="flex gap-2" style={{ flexWrap: 'wrap' }}>
                          {(c.linked_case_ids || []).map((lid) => (
                            <Link key={lid} href={`/cases/${lid}`} className="mono" style={{ fontSize: 12 }}>
                              {lid.slice(0, 8)}…
                            </Link>
                          ))}
                        </span>
                      ) : (
                        <span>—</span>
                      )}
                      <div className="text-muted" style={{ fontSize: 11, marginTop: 6 }}>
                        Suggested correlations and linking live under the <strong>Investigation</strong> tab.
                      </div>
                    </div>,
                  ],
                  [
                    'Alert ID',
                    c.alert_id ? (
                      <div className="flex gap-2 items-start flex-wrap">
                        <span className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{c.alert_id}</span>
                        <button type="button" style={{ fontSize: 11 }} onClick={() => copyText('Alert ID', c.alert_id!)}>
                          Copy
                        </button>
                        <Link href={`/alerts/${c.alert_id}`} style={{ fontSize: 12 }}>Open alert</Link>
                      </div>
                    ) : (
                      '—'
                    ),
                  ],
                  [
                    'Observables',
                    <div className="flex gap-2 items-center flex-wrap">
                      <span>{obsCount} IOC{obsCount === 1 ? '' : 's'}</span>
                      {obsCount > 0 ? (
                        <button type="button" className="btn-primary" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => setTab('observables')}>
                          View observables
                        </button>
                      ) : null}
                    </div>,
                  ],
                  [
                    'Evidence',
                    <div className="flex gap-2 items-center flex-wrap">
                      <span>
                        {evCount} file{evCount === 1 ? '' : 's'}
                        {evBytes > 0 ? ` · ${formatBytes(evBytes)}` : ''}
                      </span>
                      {evCount > 0 ? (
                        <button type="button" className="btn-primary" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => setTab('evidence')}>
                          View evidence
                        </button>
                      ) : null}
                    </div>,
                  ],
                  [
                    'SLA',
                    c.sla ? (
                      <div>
                        {c.sla.breached ? (
                          <span className="badge badge-high" style={{ marginRight: 8 }}>breached</span>
                        ) : (
                          <span className="badge badge-resolved" style={{ marginRight: 8 }}>ok</span>
                        )}
                        <span className="text-muted" style={{ fontSize: 12 }}>
                          Response and resolution targets below are shown in relative and absolute (UTC) time.
                        </span>
                      </div>
                    ) : (
                      '—'
                    ),
                  ],
                  ['SLA response due', slaDueCell(c.sla?.response_due)],
                  ['SLA resolution due', slaDueCell(c.sla?.resolution_due)],
                  [
                    'Created',
                    <span>
                      {formatUtc(c.created_at)}
                      <span className="text-muted" style={{ fontSize: 11, marginLeft: 8 }}>({relTime(c.created_at)})</span>
                    </span>,
                  ],
                  [
                    'Last updated',
                    <span>
                      {formatUtc(c.updated_at)}
                      <span className="text-muted" style={{ fontSize: 11, marginLeft: 8 }}>({relTime(c.updated_at)})</span>
                    </span>,
                  ],
                  [
                    'Last timeline event',
                    lastTimeline ? (
                      <span>
                        <span style={{ fontWeight: 500 }}>{lastTimeline.event}</span>
                        <span className="text-muted" style={{ fontSize: 12, marginLeft: 8 }}>
                          {formatUtc(lastTimeline.at)} ({relTime(lastTimeline.at)})
                        </span>
                      </span>
                    ) : (
                      '—'
                    ),
                  ],
                ].map(([k, v]) => (
                  <tr key={String(k)} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '9px 0', width: 168, color: 'var(--text-muted)', verticalAlign: 'top' }}>{k}</td>
                    <td style={{ padding: '9px 0' }}>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="card mt-4" style={{ padding: 14 }}>
              <div className="card-title mb-2">Full description</div>
              {c.description ? (
                <pre
                  style={{
                    margin: 0,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    fontSize: 13,
                    fontFamily: 'var(--font-mono, ui-monospace, monospace)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {c.description}
                </pre>
              ) : (
                <div className="empty-state">No description.</div>
              )}
            </div>
          </div>
        );
      })()}

      {tab === 'investigation' && (
        <CaseInvestigation caseId={params.id} alertId={c.alert_id || null} onRefreshCase={() => void load()} />
      )}

      {tab === 'soc' && (
        <CaseSocTab
          caseId={params.id}
          incidentCategory={c.incident_category}
          legalHold={c.legal_hold}
          shiftHandoverNotes={c.shift_handover_notes}
          auditEvents={c.audit_events}
          token={token}
          onRefresh={() => void load()}
        />
      )}

      {/* Evidence */}
      {tab === 'evidence' && (
        <div>
          <p className="text-muted mb-3" style={{ fontSize: 13 }}>
            Attach screenshots, exports, PCAP snippets, or other files for this investigation. Files are stored on the case-service
            volume (<code className="mono">CASE_EVIDENCE_DIR</code>); metadata is saved on the case record.
          </p>
          <div className="card mb-4">
            <div className="card-title mb-2">Upload file</div>
            <div className="flex gap-2" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
              <input
                type="file"
                disabled={evidenceUploading || !token}
                onChange={(e) => {
                  void uploadEvidence(e.target.files);
                  e.target.value = '';
                }}
              />
              {evidenceUploading && <span className="text-muted" style={{ fontSize: 13 }}>Uploading…</span>}
              {!token && <span className="text-muted" style={{ fontSize: 13 }}>Sign in to upload.</span>}
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Size</th>
                <th>Uploaded</th>
                <th>By</th>
                <th style={{ minWidth: 160 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(c.evidence || []).map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: 12 }}>{ev.filename || ev.id}</td>
                  <td>{formatBytes(ev.size)}</td>
                  <td className="text-muted" style={{ fontSize: 12 }}>{relTime(ev.uploaded_at)}</td>
                  <td className="text-muted" style={{ fontSize: 12 }}>{ev.uploaded_by || '—'}</td>
                  <td>
                    <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className="btn-primary"
                        style={{ fontSize: 11, padding: '4px 8px' }}
                        onClick={() => void downloadEvidence(ev.id, ev.filename || 'download')}
                      >
                        Download
                      </button>
                      <button
                        type="button"
                        className="btn-danger"
                        style={{ fontSize: 11, padding: '4px 8px' }}
                        onClick={() => void deleteEvidence(ev.id)}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {!c.evidence?.length && (
                <tr><td colSpan={5}><div className="empty-state">No evidence files yet.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Tasks */}
      {tab === 'tasks' && (
        <div>
          <div className="card mb-4">
            <div className="card-title mb-2">Add Task</div>
            <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
              <input placeholder="Task title" value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
              <input placeholder="Assign to (optional)" value={taskAssignee} onChange={(e) => setTaskAssignee(e.target.value)} style={{ width: 160 }} />
              <button className="btn-primary" onClick={addTask}>+ Add Task</button>
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr><th>Title</th><th>Assigned</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {(c.tasks || []).map((t) => (
                <tr key={t.id}>
                  <td>{t.title}</td>
                  <td className="text-muted">{t.assigned_to || '—'}</td>
                  <td>
                    <select value={t.status} onChange={(e) => updateTaskStatus(t.id, e.target.value)} style={{ fontSize: 11 }}>
                      <option value="open">open</option>
                      <option value="in-progress">in-progress</option>
                      <option value="done">done</option>
                    </select>
                  </td>
                  <td><button className="btn-danger" onClick={() => deleteTask(t.id)}>Delete</button></td>
                </tr>
              ))}
              {!c.tasks?.length && <tr><td colSpan={4}><div className="empty-state">No tasks yet.</div></td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* Comments */}
      {tab === 'comments' && (
        <div>
          <div className="card mb-4">
            <div className="card-title mb-2">Add Comment</div>
            <textarea
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Write a comment…"
              style={{ width: '100%', minHeight: 80, resize: 'vertical', marginBottom: 8 }}
            />
            <button className="btn-primary" onClick={addComment}>Post Comment</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(c.comments || []).map((cm) => (
              <div key={cm.id} className="card" style={{ padding: '12px 14px' }}>
                <div className="flex items-center gap-2 mb-1">
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{cm.author}</span>
                  <span className="text-muted" style={{ fontSize: 11 }}>{relTime(cm.at)}</span>
                  {cm.edited && <span className="badge badge-info" style={{ fontSize: 9 }}>edited</span>}
                  <button className="btn-danger ml-auto" onClick={() => deleteComment(cm.id)}>Delete</button>
                </div>
                <div style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{cm.text}</div>
              </div>
            ))}
            {!c.comments?.length && <div className="empty-state">No comments yet.</div>}
          </div>
        </div>
      )}

      {/* Timeline */}
      {tab === 'timeline' && (
        <div style={{ borderLeft: '2px solid var(--border-subtle)', paddingLeft: 16 }}>
          {(c.timeline || []).map((e, i) => (
            <div key={i} style={{ marginBottom: 12, position: 'relative' }}>
              <div style={{
                width: 8, height: 8, background: 'var(--accent-blue)', borderRadius: '50%',
                position: 'absolute', left: -20, top: 4,
              }} />
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{relTime(e.at)}</div>
              <div style={{ fontSize: 13 }}>{e.event}</div>
            </div>
          ))}
          {!c.timeline?.length && <div className="empty-state">No timeline events.</div>}
        </div>
      )}

      {/* Observables */}
      {tab === 'observables' && (
        <div>
          <div className="flex gap-3 mb-3" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
            <label className="text-muted" style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Threat intel source</span>
              <select
                className="mono"
                style={{ fontSize: 13, padding: '6px 10px', borderRadius: 6 }}
                value={intelSource}
                onChange={(e) => setIntelSource(e.target.value as IntelSource)}
              >
                <option value="opencti">OpenCTI (GraphQL search)</option>
                <option value="abuseipdb">AbuseIPDB (IP check)</option>
              </select>
            </label>
          </div>
          <p className="text-muted mb-3" style={{ fontSize: 13 }}>
            <strong>Lookup</strong> uses the source above.
            OpenCTI: <code className="mono">POST …/graphql</code> (<code className="mono">stixCyberObservables</code>) with
            <code className="mono"> OPENCTI_URL</code> + token on alert-service.
            AbuseIPDB: <code className="mono">GET /check</code> with <code className="mono">ABUSEIPDB_API_KEY</code> — IPs only.
            {OPENCTI_URL && intelSource === 'opencti' ? (
              <> Optional <strong>UI ↗</strong> opens OpenCTI in a new tab.</>
            ) : null}
          </p>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th style={{ minWidth: 220 }}>Threat intel</th>
              </tr>
            </thead>
            <tbody>
              {(c.observables || []).map((o, i) => {
                const uiHref = intelSource === 'opencti' ? openctiKnowledgeSearchUrl(o.value) : '';
                const abuseOk = observableSupportsAbuseIpdb(o);
                const lookupDisabled = intelSource === 'abuseipdb' && !abuseOk;
                return (
                  <tr key={`${i}:${o.type}:${o.value}`}>
                    <td><span className="badge badge-info">{o.type}</span></td>
                    <td className="mono">{o.value}</td>
                    <td>
                      <div className="flex gap-1" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
                        <button
                          type="button"
                          className="btn-primary"
                          style={{ fontSize: 12, padding: '4px 10px' }}
                          disabled={lookupDisabled}
                          title={lookupDisabled ? 'AbuseIPDB only supports IPv4/IPv6 addresses' : undefined}
                          onClick={() => void runIntelLookup(o, intelSource)}
                        >
                          Lookup
                        </button>
                        {intelSource === 'abuseipdb' && abuseOk ? (
                          <a
                            href={`https://www.abuseipdb.com/check/${encodeURIComponent(o.value.trim())}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontSize: 12 }}
                          >
                            AbuseIPDB ↗
                          </a>
                        ) : null}
                        {uiHref ? (
                          <a
                            href={uiHref}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontSize: 12 }}
                          >
                            OpenCTI ↗
                          </a>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!c.observables?.length && <tr><td colSpan={3}><div className="empty-state">No observables.</div></td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {intelModal && (
        <div className="modal-backdrop" onClick={() => setIntelModal(null)}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">
              {intelModal.source === 'opencti' ? 'OpenCTI' : 'AbuseIPDB'} ·{' '}
              <span className="mono" style={{ fontWeight: 400 }}>{intelModal.iocValue}</span>
              <span className="badge badge-info ml-2" style={{ fontSize: 10 }}>{intelModal.iocType}</span>
            </div>
            {intelModal.loading && (
              <div className="empty-state">
                {intelModal.source === 'opencti' ? 'Querying OpenCTI…' : 'Querying AbuseIPDB…'}
              </div>
            )}
            {intelModal.error && (
              <div className="card" style={{ padding: 12, borderColor: 'var(--sev-high)' }}>
                <div style={{ fontSize: 13, color: 'var(--sev-high)' }}>{intelModal.error}</div>
              </div>
            )}
            {!intelModal.loading && intelModal.source === 'opencti' && intelModal.opencti && (
              <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
                {intelModal.opencti.auth_hint ? (
                  <div className="card mb-3" style={{ padding: 12, borderColor: 'var(--accent-amber)' }}>
                    <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>{intelModal.opencti.auth_hint}</div>
                  </div>
                ) : null}
                {intelModal.opencti.graphql_errors ? (
                  <pre className="mono" style={{ fontSize: 11, color: 'var(--sev-high)', marginBottom: 12 }}>
                    {JSON.stringify(intelModal.opencti.graphql_errors, null, 2)}
                  </pre>
                ) : null}
                {intelModal.opencti.page_info?.globalCount != null && (
                  <div className="text-muted mb-2" style={{ fontSize: 12 }}>
                    Global count (platform): {intelModal.opencti.page_info.globalCount}
                  </div>
                )}
                {!intelModal.opencti.matches.length && !intelModal.opencti.graphql_errors ? (
                  <div className="empty-state">No matching cyber observables in OpenCTI for this search.</div>
                ) : null}
                {intelModal.opencti.matches.length > 0 && (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th className="hide-mobile">ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {intelModal.opencti.matches.map((m, j) => (
                        <tr key={m.id || j}>
                          <td><span className="badge badge-info">{m.entity_type || '—'}</span></td>
                          <td className="mono" style={{ maxWidth: 240 }}>{m.observable_value || '—'}</td>
                          <td className="mono hide-mobile" style={{ fontSize: 10 }}>{m.id || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {intelModal.opencti.matches.some((m) => m.description) ? (
                  <div style={{ marginTop: 12 }}>
                    {intelModal.opencti.matches.map((m, j) =>
                      m.description ? (
                        <div key={`d-${m.id || j}`} className="text-muted" style={{ fontSize: 12, marginBottom: 8 }}>
                          <strong>{m.observable_value}</strong>: {m.description}
                        </div>
                      ) : null,
                    )}
                  </div>
                ) : null}
              </div>
            )}
            {!intelModal.loading && intelModal.source === 'abuseipdb' && intelModal.abuseipdb && (
              <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
                {intelModal.abuseipdb.api_errors ? (
                  <pre className="mono" style={{ fontSize: 11, color: 'var(--sev-high)', marginBottom: 12 }}>
                    {JSON.stringify(intelModal.abuseipdb.api_errors, null, 2)}
                  </pre>
                ) : null}
                {intelModal.abuseipdb.data && typeof intelModal.abuseipdb.data === 'object' ? (
                  <table className="data-table mb-3">
                    <tbody>
                      {Object.entries(intelModal.abuseipdb.data).map(([k, v]) => (
                        <tr key={k}>
                          <td className="mono" style={{ fontSize: 12, width: '40%', verticalAlign: 'top' }}>{k}</td>
                          <td style={{ fontSize: 13 }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-state">No reputation data returned.</div>
                )}
                {intelModal.abuseipdb.ip ? (
                  <a
                    href={`https://www.abuseipdb.com/check/${encodeURIComponent(intelModal.abuseipdb.ip)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: 13 }}
                  >
                    Open on AbuseIPDB ↗
                  </a>
                ) : null}
              </div>
            )}
            <div className="modal-footer">
              <button type="button" onClick={() => setIntelModal(null)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className={`toast ${toastOk ? 'success' : 'error'}`}>{toast}</div>}
    </div>
  );
}
