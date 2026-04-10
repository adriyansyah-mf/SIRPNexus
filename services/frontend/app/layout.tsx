import type { Metadata } from 'next';
import './globals.css';
import AppShell from './components/AppShell';

export const metadata: Metadata = {
  title: {
    default: 'SIRP Nexus',
    template: '%s · SIRP Nexus',
  },
  description: 'Security incident response platform — alerts, cases, observables, and investigations.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
