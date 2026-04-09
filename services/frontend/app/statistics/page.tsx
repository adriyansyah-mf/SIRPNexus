import { serverJson } from '../../lib/serverGateway';
import UtcClock from '../components/UtcClock';

/* ── Types ─────────────────────────────────────────────────────────────────── */
type Alert = {
  id: string;
  severity?: string;
  source?: string;
  status?: string;
  title?: string;
  tags?: string[];
  created_at?: string;
  assigned_to?: string;
};

type Case = {
  id: string;
  title: string;
  status?: string;
  severity?: string;
  created_at?: string;
  updated_at?: string;
  tags?: string[];
};

type Observable = {
  id?: string;
  type?: string;
  value?: string;
  new?: boolean;
  created_at?: string;
  tags?: string[];
};

/* ── Compute helpers ─────────────────────────────────────────────────────────── */
function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const acc: Record<string, number> = {};
  for (const item of items) {
    const k = key(item) || 'unknown';
    acc[k] = (acc[k] || 0) + 1;
  }
  return acc;
}

function sortedEntries(map: Record<string, number>, limit = 10): [string, number][] {
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

/** Group items by 6-hour buckets over the last 7 days (28 buckets) */
function timelineBuckets(items: { created_at?: string }[], bucketHours = 6, totalDays = 7): number[] {
  const n = (totalDays * 24) / bucketHours;
  const counts = new Array(n).fill(0);
  const now = Date.now();
  const windowMs = totalDays * 24 * 60 * 60 * 1000;
  for (const item of items) {
    const ts = Date.parse(item.created_at || '');
    if (!ts) continue;
    const age = now - ts;
    if (age < 0 || age > windowMs) continue;
    const idx = Math.min(n - 1, Math.floor((age / windowMs) * n));
    counts[n - 1 - idx] += 1;
  }
  return counts;
}

function avgResolutionHours(cases: Case[]): string {
  const resolved = cases.filter((c) => c.status?.toLowerCase() === 'resolved' && c.created_at && c.updated_at);
  if (!resolved.length) return '—';
  const total = resolved.reduce((sum, c) => {
    const diff = Date.parse(c.updated_at!) - Date.parse(c.created_at!);
    return sum + Math.max(0, diff);
  }, 0);
  const avgMs = total / resolved.length;
  const hours = avgMs / 3600000;
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

/**
 * Extract pseudo-TTP tags from alerts:
 * Tags and titles are scanned for known MITRE tactic/technique keywords.
 * Real TTP coverage would need MITRE ATT&CK data attached at ingest time.
 */
const MITRE_TACTICS: Record<string, string[]> = {
  'Initial Access':     ['phishing', 'spearphishing', 'exploit', 'vpn', 'brute-force', 'bruteforce', 'credential'],
  'Execution':          ['powershell', 'cmd', 'script', 'macro', 'wscript', 'cscript', 'bash', 'python'],
  'Persistence':        ['registry', 'startup', 'cron', 'service', 'task', 'autorun', 'scheduled'],
  'Privilege Escalation': ['escalat', 'sudo', 'uac', 'token', 'impersonat', 'bypass'],
  'Defense Evasion':    ['obfuscat', 'base64', 'encode', 'disable', 'tamper', 'clear log', 'masquerade'],
  'Credential Access':  ['dump', 'lsass', 'mimikatz', 'hashdump', 'credential', 'password', 'hash'],
  'Discovery':          ['scan', 'nmap', 'enum', 'recon', 'whoami', 'ipconfig', 'systeminfo'],
  'Lateral Movement':   ['lateral', 'psexec', 'rdp', 'smb', 'pass-the-hash', 'wmi', 'winrm'],
  'Collection':         ['keylog', 'screenshot', 'clipboard', 'collect', 'exfil', 'archive'],
  'C2':                 ['beacon', 'cobalt', 'c2', 'command and control', 'dns tunnel', 'http tunnel'],
  'Exfiltration':       ['exfil', 'upload', 'transfer', 's3', 'ftp', 'curl', 'wget', 'data loss'],
  'Impact':             ['ransomware', 'wiper', 'encrypt', 'destroy', 'defac', 'dos', 'ddos'],
};

function extractTTPs(alerts: Alert[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const alert of alerts) {
    const text = `${(alert.title || '').toLowerCase()} ${(alert.tags || []).join(' ').toLowerCase()}`;
    for (const [tactic, keywords] of Object.entries(MITRE_TACTICS)) {
      if (keywords.some((kw) => text.includes(kw))) {
        counts[tactic] = (counts[tactic] || 0) + 1;
      }
    }
  }
  return counts;
}

/* ── Sub-components ─────────────────────────────────────────────────────────── */
function StatNumber({ value, label, color }: { value: string | number; label: string; color?: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '12px 0' }}>
      <div style={{ fontSize: 32, fontWeight: 700, color: color || 'var(--text-primary)', lineHeight: 1 }}>
        {value}
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {label}
      </div>
    </div>
  );
}

function HBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? Math.max(2, Math.round((count / total) * 100)) : 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
        <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</span>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
          {count} ({pct}%)
        </span>
      </div>
      <div style={{ height: 6, background: 'var(--bg-raised)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width .3s' }} />
      </div>
    </div>
  );
}

function Sparkline({ data, color, height = 48 }: { data: number[]; color: string; height?: number }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height }}>
      {data.map((v, i) => (
        <div
          key={i}
          title={String(v)}
          style={{
            flex: 1,
            height: `${Math.max(4, Math.round((v / max) * height))}px`,
            background: v === max && v > 0 ? color : `${color}55`,
            borderRadius: '2px 2px 0 0',
            transition: 'height .2s',
          }}
        />
      ))}
    </div>
  );
}

function SectionCard({ title, dot, children }: { title: string; dot?: string; children: React.ReactNode }) {
  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div className="card-header">
        <span className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          {dot && <span className={`dot ${dot}`}></span>}
          {title}
        </span>
      </div>
      <div style={{ padding: '4px 0' }}>{children}</div>
    </div>
  );
}

/* ── Page ───────────────────────────────────────────────────────────────────── */
export default async function StatisticsPage() {
  const [alerts, cases, observables] = await Promise.all([
    serverJson<Alert[]>('/alerts/alerts'),
    serverJson<Case[]>('/cases/cases'),
    serverJson<Observable[]>('/observables/observables'),
  ]);

  /* ── Alert stats ──────────────────────────────────────────────────────── */
  const alertTotal = alerts.length;
  const alertBySev = countBy(alerts, (a) => a.severity?.toLowerCase() || 'unknown');
  const alertByStatus = countBy(alerts, (a) => a.status?.toLowerCase() || 'new');
  const alertBySource = countBy(alerts, (a) => (a.source || 'unknown').toLowerCase());
  const alertTimeline = timelineBuckets(alerts);
  const alertCritical = alertBySev['critical'] || 0;
  const alertOpen = alerts.filter((a) => a.status?.toLowerCase() !== 'closed').length;
  const alertAssigned = alerts.filter((a) => a.assigned_to).length;

  /* ── Case stats ───────────────────────────────────────────────────────── */
  const caseTotal = cases.length;
  const caseByStatus = countBy(cases, (c) => c.status?.toLowerCase() || 'open');
  const caseBySev = countBy(cases, (c) => c.severity?.toLowerCase() || 'unknown');
  const caseOpen = cases.filter((c) => !['resolved', 'closed'].includes(c.status?.toLowerCase() || '')).length;
  const caseResolved = (caseByStatus['resolved'] || 0) + (caseByStatus['closed'] || 0);
  const mttr = avgResolutionHours(cases);
  const caseTimeline = timelineBuckets(cases);

  /* ── Observable stats ─────────────────────────────────────────────────── */
  const obsTotal = observables.length;
  const obsByType = countBy(observables, (o) => o.type?.toLowerCase() || 'unknown');
  const obsNew = observables.filter((o) => o.new).length;
  const obsTimeline = timelineBuckets(observables);

  /* ── TTP stats ────────────────────────────────────────────────────────── */
  const ttpCounts = extractTTPs(alerts);
  const ttpTotal = Object.values(ttpCounts).reduce((a, b) => a + b, 0);
  const ttpSorted = sortedEntries(ttpCounts, 12);
  const topTTP = ttpSorted[0]?.[0] || '—';
  const coveredTactics = Object.keys(ttpCounts).length;
  const totalTactics = Object.keys(MITRE_TACTICS).length;
  const ttpCoverage = Math.round((coveredTactics / totalTactics) * 100);

  /* ── Tag cloud (from alerts) ──────────────────────────────────────────── */
  const tagMap: Record<string, number> = {};
  for (const a of alerts) {
    for (const t of a.tags || []) {
      tagMap[t] = (tagMap[t] || 0) + 1;
    }
  }
  const topTags = sortedEntries(tagMap, 15);

  const SEV_COLORS: Record<string, string> = {
    critical: 'var(--sev-critical)',
    high:     'var(--sev-high)',
    medium:   'var(--sev-medium)',
    low:      'var(--sev-low)',
    unknown:  'var(--text-muted)',
  };

  const STATUS_COLORS: Record<string, string> = {
    new:        'var(--status-new)',
    triaged:    'var(--status-triaged)',
    escalated:  'var(--status-escalated)',
    closed:     'var(--status-closed)',
    open:       'var(--status-open)',
    resolved:   'var(--status-resolved)',
    'in-progress': 'var(--accent-amber)',
  };

  const OBS_COLORS: Record<string, string> = {
    ip:     'var(--accent-blue)',
    domain: 'var(--accent-amber)',
    hash:   'var(--sev-critical)',
    url:    'var(--sev-high)',
    email:  'var(--accent-green)',
    unknown:'var(--text-muted)',
  };

  const TTP_COLOR = 'var(--accent-blue)';

  return (
    <div>
      {/* Header */}
      <div className="page-hd">
        <div>
          <h1>Statistics</h1>
          <div className="page-meta">All-time · auto-refreshes on page load · <UtcClock /></div>
        </div>
      </div>

      {/* ── Top KPI row ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
        {[
          { label: 'Total Alerts',    value: alertTotal,  color: 'var(--text-primary)' },
          { label: 'Total Cases',     value: caseTotal,   color: 'var(--text-primary)' },
          { label: 'IOCs Tracked',    value: obsTotal,    color: 'var(--text-primary)' },
          { label: 'TTPs Detected',   value: coveredTactics, color: 'var(--text-primary)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="kpi-box" style={{ textAlign: 'center' }}>
            <div className="kpi-label">{label}</div>
            <div className="kpi-value" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* ── 2-column grid ───────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* ── ALERTS STATISTICS ─────────────────────────────────────────────── */}
        <SectionCard title="Alerts Statistics" dot="dot-red">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 16, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <StatNumber value={alertCritical} label="Critical" color="var(--sev-critical)" />
            <StatNumber value={alertOpen}     label="Open"     color="var(--sev-medium)" />
            <StatNumber value={alertAssigned} label="Assigned" color="var(--accent-blue)" />
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By Severity
            </div>
            {sortedEntries(alertBySev).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={alertTotal} color={SEV_COLORS[k] || 'var(--accent-blue)'} />
            ))}
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By Status
            </div>
            {sortedEntries(alertByStatus).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={alertTotal} color={STATUS_COLORS[k] || 'var(--text-muted)'} />
            ))}
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By Source (top 5)
            </div>
            {sortedEntries(alertBySource, 5).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={alertTotal} color="var(--accent-blue)" />
            ))}
          </div>

          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 6 }}>
              Volume — last 7 days (6h buckets)
            </div>
            <Sparkline data={alertTimeline} color="var(--sev-critical)" />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-muted)', marginTop: 3, fontFamily: 'monospace' }}>
              <span>7d ago</span><span>now</span>
            </div>
          </div>
        </SectionCard>

        {/* ── CASES STATISTICS ──────────────────────────────────────────────── */}
        <SectionCard title="Cases Statistics" dot="dot-amber">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 16, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <StatNumber value={caseOpen}     label="Open"     color="var(--sev-medium)" />
            <StatNumber value={caseResolved} label="Resolved" color="var(--accent-green)" />
            <StatNumber value={mttr}         label="Avg MTTR" color="var(--accent-blue)" />
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By Status
            </div>
            {sortedEntries(caseByStatus).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={caseTotal} color={STATUS_COLORS[k] || 'var(--text-muted)'} />
            ))}
            {!caseTotal && <div className="empty-state">No cases yet.</div>}
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By Severity
            </div>
            {sortedEntries(caseBySev).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={caseTotal} color={SEV_COLORS[k] || 'var(--accent-blue)'} />
            ))}
            {!Object.keys(caseBySev).length && <div className="empty-state">No cases yet.</div>}
          </div>

          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 6 }}>
              Volume — last 7 days (6h buckets)
            </div>
            <Sparkline data={caseTimeline} color="var(--accent-amber)" />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-muted)', marginTop: 3, fontFamily: 'monospace' }}>
              <span>7d ago</span><span>now</span>
            </div>
          </div>
        </SectionCard>

        {/* ── OBSERVABLES STATISTICS ────────────────────────────────────────── */}
        <SectionCard title="Observables Statistics" dot="dot-cyan">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 8, marginBottom: 16, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <StatNumber value={obsNew} label="New (dedupe window)" color="var(--accent-blue)" />
            <StatNumber value={obsTotal} label="Total tracked" color="var(--accent-cyan)" />
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
              By IOC Type
            </div>
            {sortedEntries(obsByType).map(([k, v]) => (
              <HBar key={k} label={k} count={v} total={obsTotal} color={OBS_COLORS[k] || 'var(--accent-blue)'} />
            ))}
            {!obsTotal && <div className="empty-state">No observables yet.</div>}
          </div>

          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 6 }}>
              IOC Ingestion — last 7 days (6h buckets)
            </div>
            <Sparkline data={obsTimeline} color="var(--accent-cyan)" />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-muted)', marginTop: 3, fontFamily: 'monospace' }}>
              <span>7d ago</span><span>now</span>
            </div>
          </div>
        </SectionCard>

        {/* ── TTPs STATISTICS ───────────────────────────────────────────────── */}
        <SectionCard title="TTPs Statistics (MITRE ATT&CK)" dot="dot-red">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 16, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <StatNumber value={`${coveredTactics}/${totalTactics}`} label="Tactics seen"  color="var(--sev-critical)" />
            <StatNumber value={ttpTotal}                            label="TTP matches"   color="var(--sev-medium)" />
            <StatNumber value={`${ttpCoverage}%`}                  label="Coverage"      color="var(--accent-blue)" />
          </div>

          {/* Coverage bar */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
              <span>MITRE ATT&CK Tactic Coverage</span>
              <span>{ttpCoverage}%</span>
            </div>
            <div style={{ height: 8, background: 'var(--bg-raised)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ width: `${ttpCoverage}%`, height: '100%', background: 'linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))', borderRadius: 4 }} />
            </div>
          </div>

          {ttpSorted.length > 0 ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
                Tactic frequency
              </div>
              {ttpSorted.map(([tactic, count]) => (
                <HBar key={tactic} label={tactic} count={count} total={ttpTotal} color={TTP_COLOR} />
              ))}
            </div>
          ) : (
            <div>
              <div className="empty-state" style={{ paddingTop: 12, paddingBottom: 12 }}>
                No TTP keywords detected in current alerts.<br />
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  TTPs are inferred from alert titles and tags. Enrich alerts from Wazuh, Splunk, or manual tagging to populate this panel.
                </span>
              </div>
              {/* Show all detectable tactics as reference */}
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: 8 }}>
                  Detectable tactics (0 matched)
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {Object.keys(MITRE_TACTICS).map((t) => (
                    <span key={t} className="badge badge-new" style={{ fontSize: 10 }}>{t}</span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Top TTP callout */}
          {ttpSorted.length > 0 && (
            <div style={{ marginTop: 14, padding: '10px 12px', background: 'var(--bg-raised)', borderLeft: '3px solid var(--sev-critical)', borderRadius: 3 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>Most frequent tactic</div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{topTTP}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                {ttpCounts[topTTP]} alert(s) matched
              </div>
            </div>
          )}
        </SectionCard>
      </div>

      {/* ── Tag cloud ──────────────────────────────────────────────────────── */}
      {topTags.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">Top Alert Tags</span>
            <span className="text-muted" style={{ fontSize: 11 }}>{topTags.length} unique tags</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {topTags.map(([tag, count]) => {
              const size = 10 + Math.min(6, Math.round(count / 2));
              return (
                <span
                  key={tag}
                  className="tag"
                  style={{ fontSize: size, padding: `2px ${size - 4}px` }}
                  title={`${count} alert(s)`}
                >
                  {tag} <span style={{ color: 'var(--accent-blue)', fontSize: 10 }}>{count}</span>
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
