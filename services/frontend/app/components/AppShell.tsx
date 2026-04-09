'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import AuthBar from './AuthBar';
import UtcClock from './UtcClock';

const NAV_ITEMS = [
  { label: 'Dashboard',   href: '/' },
  { label: 'Alerts',      href: '/alerts' },
  { label: 'Cases',       href: '/cases' },
  { label: 'Observables', href: '/observables' },
  { label: 'Forensics',   href: '/analyzers' },
  { label: 'Playbooks',   href: '/playbooks' },
  { label: 'Statistics',  href: '/statistics' },
  { label: 'Admin',       href: '/admin' },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  if (pathname === '/login') return <>{children}</>;

  return (
    <div className="app-shell">
      <header className="app-topnav">
        <div className="app-brand">SIRP<span>Nexus</span></div>
        <nav className="app-nav">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href)) ? 'active' : ''}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="app-auth">
          <AuthBar />
        </div>
      </header>
      <main className="app-main">{children}</main>
      <footer className="status-bar">
        <div className="status-item"><span className="dot dot-green"></span>API Gateway</div>
        <div className="status-item"><span className="dot dot-green"></span>Kafka</div>
        <div className="status-item"><span className="dot dot-green"></span>PostgreSQL</div>
        <div className="status-clock"><UtcClock /></div>
      </footer>
    </div>
  );
}
