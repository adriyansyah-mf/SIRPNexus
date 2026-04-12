import { cookies } from 'next/headers';
import type { NextRequest } from 'next/server';

function decodeCookieToken(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Authorization for admin API routes: Bearer header or HttpOnly sirp_token cookie. */
export function resolveBearer(req: NextRequest): string | null {
  const h = req.headers.get('authorization');
  if (h?.toLowerCase().startsWith('bearer ')) return h;
  const t = cookies().get('sirp_token')?.value;
  if (!t) return null;
  return `Bearer ${decodeCookieToken(t)}`;
}
