'use client';

import { useEffect, useState } from 'react';

type StreamEvent = {
  topic: string;
  offset: number;
  payload: string;
};

export default function RealtimeFeed() {
  const [events, setEvents] = useState<StreamEvent[]>([]);

  useEffect(() => {
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/stream/events';
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data) as StreamEvent;
        setEvents((prev) => [parsed, ...prev].slice(0, 20));
      } catch {
        // Ignore malformed events.
      }
    };

    return () => ws.close();
  }, []);

  return (
    <section>
      <h3>Live Event Stream</h3>
      <ul>
        {events.map((e, idx) => (
          <li key={`${e.topic}-${e.offset}-${idx}`}>
            [{e.topic}] {e.payload.slice(0, 140)}
          </li>
        ))}
      </ul>
    </section>
  );
}
