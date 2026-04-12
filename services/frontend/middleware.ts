import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/logout', '/api/health'];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (pathname.startsWith('/sirp-api/')) {
    const token = request.cookies.get('sirp_token')?.value;
    const auth = request.headers.get('authorization');
    if (token && !auth?.toLowerCase().startsWith('bearer ')) {
      let raw = token;
      try {
        raw = decodeURIComponent(token);
      } catch {
        /* cookie value may be unencoded */
      }
      const reqHeaders = new Headers(request.headers);
      reqHeaders.set('authorization', `Bearer ${raw}`);
      return NextResponse.next({ request: { headers: reqHeaders } });
    }
    return NextResponse.next();
  }

  if (
    PUBLIC_PATHS.some((p) => pathname.startsWith(p)) ||
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/favicon')
  ) {
    return NextResponse.next();
  }

  const token =
    request.cookies.get('sirp_token')?.value ||
    request.headers.get('authorization')?.replace(/^Bearer\s+/i, '');

  if (!token) {
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    url.searchParams.set('next', pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
