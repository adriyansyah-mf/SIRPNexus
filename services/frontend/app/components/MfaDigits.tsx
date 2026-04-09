'use client';

import { useRef } from 'react';

export default function MfaDigits() {
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  const onInput = (idx: number, value: string) => {
    const next = value.replace(/\D/g, '').slice(-1);
    const current = refs.current[idx];
    if (current) {
      current.value = next;
    }
    if (next && idx < refs.current.length - 1) {
      refs.current[idx + 1]?.focus();
    }
  };

  const onKeyDown = (idx: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !refs.current[idx]?.value && idx > 0) {
      refs.current[idx - 1]?.focus();
    }
  };

  return (
    <div className="mfa-row">
      {Array.from({ length: 6 }).map((_, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          className="mfa-digit"
          type="text"
          inputMode="numeric"
          maxLength={1}
          onInput={(e) => onInput(i, e.currentTarget.value)}
          onKeyDown={(e) => onKeyDown(i, e)}
        />
      ))}
    </div>
  );
}
