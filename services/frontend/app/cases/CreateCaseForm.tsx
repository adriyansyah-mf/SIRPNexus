'use client';

import { CLIENT_API_PREFIX } from '../../lib/clientApi';
import { useRouter } from 'next/navigation';
import { FormEvent, useState } from 'react';

export default function CreateCaseForm() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [owner, setOwner] = useState('');
  const [tagsRaw, setTagsRaw] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const token = typeof window !== 'undefined' ? (localStorage.getItem('sirp_token') || '') : '';

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setError('Title is required');
      return;
    }
    if (!token) {
      setError('Sign in to create a case');
      return;
    }
    setLoading(true);
    setError('');
    const tags = tagsRaw
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    const res = await fetch(`${CLIENT_API_PREFIX}/cases/cases`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        title: title.trim(),
        description: description.trim(),
        severity,
        owner: owner.trim(),
        tags,
      }),
    });
    const data = (await res.json().catch(() => ({}))) as { detail?: string | { msg?: string }[]; id?: string };
    setLoading(false);
    if (!res.ok) {
      const d = data.detail;
      const msg =
        typeof d === 'string'
          ? d
          : Array.isArray(d)
            ? d.map((x) => x.msg || JSON.stringify(x)).join('; ')
            : `Failed (${res.status})`;
      setError(msg);
      return;
    }
    if (data.id) {
      setOpen(false);
      setTitle('');
      setDescription('');
      setTagsRaw('');
      router.push(`/cases/${data.id}`);
      router.refresh();
    }
  };

  return (
    <>
      <button type="button" className="btn-primary" onClick={() => setOpen(true)}>
        + New case
      </button>
      {open && (
    <div className="modal-backdrop" onClick={() => { setOpen(false); setError(''); }}>
      <div className="modal" style={{ maxWidth: 480 }} onClick={(e) => e.stopPropagation()}>
      <div className="card-title mb-2">New case (no alert)</div>
      <p className="text-muted mb-3" style={{ fontSize: 12 }}>
        Create an empty case for proactive work, third-party reports, or tasks that did not start from an alert.
      </p>
      <form onSubmit={(e) => void submit(e)} className="form-row">
        {error && <div className="login-error" style={{ marginBottom: 8 }}>{error}</div>}
        <div>
          <label>Title</label>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Short summary"
            required
            className="w-full"
          />
        </div>
        <div>
          <label>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Context, scope, links…"
            rows={4}
            className="w-full"
            style={{ resize: 'vertical' }}
          />
        </div>
        <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 120 }}>
            <label>Severity</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full">
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 120 }}>
            <label>Owner (optional)</label>
            <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="team / analyst" className="w-full" />
          </div>
        </div>
        <div>
          <label>Tags (comma-separated)</label>
          <input
            value={tagsRaw}
            onChange={(e) => setTagsRaw(e.target.value)}
            placeholder="phishing, vendor-x"
            className="w-full"
          />
        </div>
        <div className="flex gap-2" style={{ marginTop: 8 }}>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating…' : 'Create case'}
          </button>
          <button type="button" onClick={() => { setOpen(false); setError(''); }}>
            Cancel
          </button>
        </div>
      </form>
      </div>
    </div>
      )}
    </>
  );
}
