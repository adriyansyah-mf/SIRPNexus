'use client';

import { useEffect, useState } from 'react';

export default function AuthBar() {
  const [hasToken, setHasToken] = useState(false);

  useEffect(() => {
    setHasToken(Boolean(localStorage.getItem('sirp_token')));
  }, []);

  const logout = () => {
    localStorage.removeItem('sirp_token');
    document.cookie = 'sirp_token=; path=/; max-age=0';
    window.location.href = '/login';
  };

  if (!hasToken) {
    return (
      <a href="/login" className="btn btn-primary" style={{ fontSize: 12, padding: '4px 12px' }}>
        Login
      </a>
    );
  }

  return (
    <button onClick={logout} style={{ fontSize: 12, padding: '4px 12px' }}>
      Logout
    </button>
  );
}
