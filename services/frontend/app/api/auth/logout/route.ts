import { NextResponse } from 'next/server';

export async function POST() {
  const secure =
    process.env.COOKIE_SECURE === 'true' ||
    (process.env.COOKIE_SECURE !== 'false' && process.env.NODE_ENV === 'production');
  const tail = secure ? '; Secure' : '';
  const res = NextResponse.json({ ok: true });
  res.headers.append(
    'Set-Cookie',
    `sirp_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${tail}`,
  );
  return res;
}
