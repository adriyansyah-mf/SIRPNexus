import { NextRequest, NextResponse } from 'next/server';

const gateway = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

export async function GET(req: NextRequest) {
  const auth = req.headers.get('authorization') || '';
  if (!auth) return NextResponse.json({ detail: 'Missing authorization' }, { status: 401 });

  const resp = await fetch(`${gateway}/secrets/secrets`, {
    headers: { authorization: auth },
    cache: 'no-store',
  });
  const data = await resp.json().catch(() => ({}));
  return NextResponse.json(data, { status: resp.status });
}

export async function PUT(req: NextRequest) {
  const auth = req.headers.get('authorization') || '';
  if (!auth) return NextResponse.json({ detail: 'Missing authorization' }, { status: 401 });

  const body = await req.json();
  const key = body?.key;
  const value = body?.value;
  if (!key || typeof value !== 'string') {
    return NextResponse.json({ detail: 'Invalid payload' }, { status: 400 });
  }

  const resp = await fetch(`${gateway}/secrets/secrets/${encodeURIComponent(key)}`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      authorization: auth,
    },
    body: JSON.stringify({ value }),
  });
  const data = await resp.json().catch(() => ({}));
  return NextResponse.json(data, { status: resp.status });
}
