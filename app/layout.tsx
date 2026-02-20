import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'VibeScan — Security Scanner for AI-Built Apps',
  description: 'Vibe-coded apps are fast to build — but are they secure? VibeScan finds what you missed. Free security scanner for Lovable, Bolt, Cursor, and V0 apps.',
  keywords: ['security scanner', 'lovable', 'bolt', 'cursor', 'v0', 'vibe coding', 'web security', 'API key exposure'],
  openGraph: {
    title: 'VibeScan — Is your app leaking?',
    description: 'Free security scanner for AI/vibe-coded apps. Find exposed secrets, missing headers, and sensitive paths in seconds.',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        {children}
      </body>
    </html>
  );
}
