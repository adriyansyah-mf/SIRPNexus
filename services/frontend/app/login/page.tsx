'use client';

import { FormEvent, useState } from 'react';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
    const data = await resp.json().catch(() => ({}));
    setLoading(false);

    if (!resp.ok || !data.ok) {
      setError(data.detail || 'Invalid credentials');
      return;
    }

    const params = new URLSearchParams(window.location.search);
    window.location.href = params.get('next') || '/';
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-logo">
          <div className="brand-name">SIRP<span>Nexus</span></div>
          <div className="brand-sub">Security Incident Response Platform</div>
        </div>

        <div className="login-divider"></div>

        <div className="login-title">Sign in</div>
        <p>Enter your credentials to access the platform</p>

        {error && <div className="login-error">{error}</div>}

        <form onSubmit={submit} className="form-row">
          <div>
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
              required
              className="w-full"
            />
          </div>
          <div>
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
              className="w-full"
            />
          </div>
          <button type="submit" disabled={loading} className="btn-primary w-full" style={{ justifyContent: 'center', padding: '8px' }}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
