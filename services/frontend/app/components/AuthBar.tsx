'use client';

import { usePathname } from 'next/navigation';

export default function AuthBar() {
  const pathname = usePathname();

  if (pathname === '/login') {
    return null;
  }

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
    window.location.href = '/login';
  };

  return (
    <button type="button" onClick={() => void logout()} style={{ fontSize: 12, padding: '4px 12px' }}>
      Logout
    </button>
  );
}
