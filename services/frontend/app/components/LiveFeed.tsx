'use client';

import { browserStreamEventsUrl } from '../../lib/wsUrl';
import { useEffect, useRef, useState } from 'react';

type FeedEvent = {
  topic: string;
  payload: string;
  at: string;
};

const MAX_EVENTS = 30;

const ICON: Record<string, string> = {
  'alerts.normalized': '⚠',
  'cases.updated': '⬡',
};

const ICON_CLS: Record<string, string> = {
  'alerts.normalized': 'fi-red',
  'cases.updated': 'fi-amber',
};

function topicLabel(topic: string): string {
  if (topic.startsWith('alerts')) return 'ALERT';
  if (topic.startsWith('cases')) return 'CASE';
  return topic.toUpperCase();
}

function eventSummary(topic: string, payload: string): string {
  try {
    const d = JSON.parse(payload);
    if (topic.startsWith('alerts')) return d.title || 'New alert ingested';
    if (topic.startsWith('cases')) return `${d.event || 'event'}: ${d.case?.title || d.case_id || '?'}`;
  } catch {
    // fallback
  }
  return payload.slice(0, 80);
}

export default function LiveFeed() {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    const url = browserStreamEventsUrl();

    const connect = () => {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect after 5s
        reconnectRef.current = setTimeout(connect, 5000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          setEvents((prev) => [
            { topic: msg.topic, payload: msg.payload, at: new Date().toISOString() },
            ...prev,
          ].slice(0, MAX_EVENTS));
        } catch {
          // ignore
        }
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, []);

  return (
    <div>
      <div className="card-header">
        <span className="card-title">Live Activity</span>
        <span className="flex items-center gap-1" style={{ fontSize: 11, color: connected ? 'var(--accent-green)' : 'var(--text-muted)' }}>
          <span className={`dot ${connected ? 'dot-green' : 'dot-amber'}`}></span>
          {connected ? 'Connected' : 'Reconnecting…'}
        </span>
      </div>
      <div style={{ maxHeight: 280, overflowY: 'auto' }}>
        {events.map((e, i) => (
          <div key={i} className="feed-item">
            <div className={`feed-icon ${ICON_CLS[e.topic] || 'fi-cyan'}`}>
              {ICON[e.topic] || '◎'}
            </div>
            <div className="feed-content">
              <div className="feed-text">{eventSummary(e.topic, e.payload)}</div>
              <div className="feed-time">{topicLabel(e.topic)}</div>
            </div>
          </div>
        ))}
        {!events.length && (
          <div className="feed-item">
            <div className="feed-icon fi-cyan">◎</div>
            <div className="feed-content">
              <div className="feed-text">Awaiting events…</div>
              <div className="feed-time">KAFKA STREAM</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
