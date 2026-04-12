import { NextRequest, NextResponse } from 'next/server';
import { resolveBearer } from '../../../../lib/adminAuth';

const GW = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

async function fwd(req: NextRequest, method: string, body?: unknown) {
  const auth = resolveBearer(req);
  if (!auth) return NextResponse.json({ detail: 'Missing authorization' }, { status: 401 });

  const resp = await fetch(`${GW}/auth/users`, {
    method,
    headers: {
      authorization: auth,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    cache: 'no-store',
  });
  const data = await resp.json().catch(() => ({}));
  return NextResponse.json(data, { status: resp.status });
}

export async function GET(req: NextRequest) {
  return fwd(req, 'GET');
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  return fwd(req, 'POST', body);
}
