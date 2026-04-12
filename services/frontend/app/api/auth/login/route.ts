import { NextRequest, NextResponse } from 'next/server';

const GW = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

export async function POST(req: NextRequest) {
  try {
    const { username, password } = await req.json();
    if (!username || !password) {
      return NextResponse.json({ detail: 'username and password required' }, { status: 400 });
    }

    const resp = await fetch(`${GW.replace(/\/$/, '')}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.access_token) {
      return NextResponse.json(data, { status: resp.status });
    }

    const secure =
      process.env.COOKIE_SECURE === 'true' ||
      (process.env.COOKIE_SECURE !== 'false' && process.env.NODE_ENV === 'production');
    const maxAge = typeof data.expires_in === 'number' ? data.expires_in : 28800;
    const raw = String(data.access_token);
    const cookieParts = [
      `sirp_token=${encodeURIComponent(raw)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
    ];
    if (secure) cookieParts.push('Secure');

    const out = NextResponse.json({ ok: true, role: data.role, expires_in: maxAge }, { status: 200 });
    out.headers.append('Set-Cookie', cookieParts.join('; '));
    return out;
  } catch {
    return NextResponse.json({ detail: 'Login request failed' }, { status: 500 });
  }
}
