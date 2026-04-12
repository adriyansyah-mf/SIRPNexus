/**
 * WebSocket URL for /stream/events (browser).
 * Same origin as the UI: server.js proxies upgrades to API_GATEWAY_URL (cookie auth, no ?token=).
 */
export function browserStreamEventsUrl(): string {
  const envWs = process.env.NEXT_PUBLIC_WS_URL?.trim();
  if (envWs) {
    let base = envWs.replace(/\/$/, '');
    if (!base.includes('stream/events')) {
      base = `${base}/stream/events`;
    }
    return base;
  }
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/stream/events`;
  }
  return 'ws://127.0.0.1:3000/stream/events';
}
