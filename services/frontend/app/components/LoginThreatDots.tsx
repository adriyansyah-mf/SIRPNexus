'use client';

import { useMemo } from 'react';

type Dot = { left: number; top: number; color: string; delay: number; duration: number };

export default function LoginThreatDots() {
  const dots = useMemo<Dot[]>(() => {
    const colors = ['#00d4ff', '#ff2d55', '#ffaa00', '#00ff88'];
    return Array.from({ length: 18 }).map(() => ({
      left: Math.random() * 100,
      top: Math.random() * 100,
      color: colors[Math.floor(Math.random() * colors.length)],
      delay: Math.random() * 4,
      duration: 3 + Math.random() * 3,
    }));
  }, []);

  return (
    <div className="threat-dots">
      {dots.map((d, i) => (
        <span
          key={i}
          className="tdot"
          style={{
            left: `${d.left}%`,
            top: `${d.top}%`,
            color: d.color,
            background: d.color,
            animationDelay: `${d.delay}s`,
            animationDuration: `${d.duration}s`,
            boxShadow: '0 0 8px currentColor',
          }}
        />
      ))}
    </div>
  );
}
