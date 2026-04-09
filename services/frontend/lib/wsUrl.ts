/**
 * WebSocket URL for /stream/events (browser). Uses page hostname so remote access works.
 */
export function browserStreamEventsUrl(token: string): string {
  const envWs = process.env.NEXT_PUBLIC_WS_URL?.trim();
  let base: string;
  if (envWs) {
    base = envWs.replace(/\/$/, '');
    if (!base.includes('stream/events')) {
      base = `${base}/stream/events`;
    }
  } else if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const port = process.env.NEXT_PUBLIC_GATEWAY_PORT || '8000';
    base = `${proto}//${window.location.hostname}:${port}/stream/events`;
  } else {
    base = 'ws://127.0.0.1:8000/stream/events';
  }
  const q = token ? `?token=${encodeURIComponent(token)}` : '';
  return `${base}${q}`;
}
