'use client';

import { browserStreamEventsUrl } from '../../lib/wsUrl';
import { useEffect, useState } from 'react';

type StreamEvent = {
  topic: string;
  offset: number;
  payload: string;
};

export default function RealtimeFeed() {
  const [events, setEvents] = useState<StreamEvent[]>([]);

  useEffect(() => {
    const token = localStorage.getItem('sirp_token') || '';
    const ws = new WebSocket(browserStreamEventsUrl(token));

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
