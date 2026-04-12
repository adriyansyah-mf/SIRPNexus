/**
 * Browser-side API base: same origin as the UI, proxied by Next.js → API_GATEWAY_URL.
 * Avoids calling http://localhost:8000 from the user's machine when the app is opened via server IP/DNS.
 */
export const CLIENT_API_PREFIX = '/sirp-api';

/** Session JWT is HttpOnly; middleware injects Authorization for /sirp-api. */
export const credFetch: RequestInit = { credentials: 'include' };
