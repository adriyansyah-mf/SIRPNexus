import { NextRequest, NextResponse } from 'next/server';

const GW = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

export async function POST(req: NextRequest) {
  try {
    const { username, password } = await req.json();
    if (!username || !password) {
      return NextResponse.json({ detail: 'username and password required' }, { status: 400 });
    }

    // Proxy to gateway user DB (bcrypt, lockout, multi-user)
    const resp = await fetch(`${GW}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await resp.json().catch(() => ({}));
    return NextResponse.json(data, { status: resp.status });
  } catch {
    return NextResponse.json({ detail: 'Login request failed' }, { status: 500 });
  }
}
