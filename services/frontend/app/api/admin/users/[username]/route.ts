import { NextRequest, NextResponse } from 'next/server';
import { resolveBearer } from '../../../../../lib/adminAuth';

const GW = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

async function fwdUser(req: NextRequest, username: string, subpath: string, method: string, body?: unknown) {
  const auth = resolveBearer(req);
  if (!auth) return NextResponse.json({ detail: 'Missing authorization' }, { status: 401 });

  const url = `${GW}/auth/users/${encodeURIComponent(username)}/${subpath}`;
  const resp = await fetch(url, {
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

async function fwdDelete(req: NextRequest, username: string) {
  const auth = resolveBearer(req);
  if (!auth) return NextResponse.json({ detail: 'Missing authorization' }, { status: 401 });

  const resp = await fetch(`${GW}/auth/users/${encodeURIComponent(username)}`, {
    method: 'DELETE',
    headers: { authorization: auth },
    cache: 'no-store',
  });
  const data = await resp.json().catch(() => ({}));
  return NextResponse.json(data, { status: resp.status });
}

export async function PUT(req: NextRequest, { params }: { params: { username: string } }) {
  const body = await req.json();
  const subpath = body.password ? 'password' : 'role';
  return fwdUser(req, params.username, subpath, 'PUT', body);
}

export async function DELETE(req: NextRequest, { params }: { params: { username: string } }) {
  return fwdDelete(req, params.username);
}
