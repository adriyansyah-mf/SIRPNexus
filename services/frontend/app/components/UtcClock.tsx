'use client';

import { useEffect, useState } from 'react';

export default function UtcClock() {
  const [clock, setClock] = useState('--:--:-- UTC');

  useEffect(() => {
    const update = () => {
      const n = new Date();
      setClock(`${n.toISOString().slice(11, 19)} UTC`);
    };
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, []);

  return <>{clock}</>;
}
