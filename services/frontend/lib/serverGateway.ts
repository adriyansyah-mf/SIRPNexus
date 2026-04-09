import { cookies } from 'next/headers';

const SERVER_GATEWAY_URL = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

/** Server Components: call gateway from the Next container with session cookie → Bearer. */
export async function serverFetchGateway(path: string, init?: RequestInit): Promise<Response> {
  const token = cookies().get('sirp_token')?.value;
  const headers = new Headers(init?.headers);
  if (token) headers.set('authorization', `Bearer ${token}`);
  const p = path.startsWith('/') ? path : `/${path}`;
  return fetch(`${SERVER_GATEWAY_URL}${p}`, { ...init, headers, cache: 'no-store' });
}

export async function serverJson<T>(path: string): Promise<T> {
  try {
    const res = await serverFetchGateway(path);
    if (!res.ok) return [] as T;
    return (await res.json()) as T;
  } catch {
    return [] as T;
  }
}
