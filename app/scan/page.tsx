'use client';

import { useEffect, useState, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Suspense } from 'react';
import FixPromptModal from '@/components/FixPromptModal';
import { severityLabels, classifyUrl, checkCopy } from '@/lib/check-copy';

interface ScanCheck {
  id: string;
  category: 'pages' | 'headers' | 'secrets' | 'exposure' | 'ssl';
  name: string;
  status: 'critical' | 'warning' | 'pass' | 'info';
  detail: string;
  value?: string;
}

interface ExposedTable {
  name: string;
  columns: string[];
  sampleRows: Record<string, unknown>[];
  totalRows?: number;
  rls: boolean;
}

interface DataLeaks {
  supabaseUrl: string;
  keyPreview: string;
  tables: ExposedTable[];
  blockedTables: string[];
  tablesFound: number;
  openTables: number;
}

interface ExposedDataItem {
  kind: 'file' | 'secret' | 'database';
  label: string;
  description: string;
  preview?: string;
  severity: 'critical' | 'warning';
  dataLeaks?: DataLeaks;
}

interface ScanReport {
  url: string;
  scannedAt: string;
  score: number;
  summary: { critical: number; warnings: number; passed: number };
  discoveredUrls: string[];
  checks: ScanCheck[];
  dataLeaks?: DataLeaks | null;
}

const TERMINAL_STEPS = [
  '🔍 Resolving domain...',
  '🗺️  Fetching sitemap.xml...',
  '🤖 Reading robots.txt...',
  '🔗 Crawling homepage links...',
  '🚪 Checking for exposed files (.env, .git)...',
  '🛡️  Inspecting security headers...',
  '🔑 Scanning JavaScript bundles for secrets...',
  '🗄️  Probing database with exposed credentials...',
  '🌐 Testing CORS policy...',
  '🔒 Verifying SSL / HTTPS...',
  '📊 Calculating your security score...',
];

function ScoreBadge({ score }: { score: number }) {
  const isGood = score >= 70;
  const isMid = score >= 40 && score < 70;

  const config = isGood
    ? { bg: 'bg-green-50', border: 'border-green-300', text: 'text-green-700', ring: 'ring-green-200', label: "You're in good shape", sublabel: 'A few things to review' }
    : isMid
    ? { bg: 'bg-amber-50', border: 'border-amber-300', text: 'text-amber-700', ring: 'ring-amber-200', label: 'Room for improvement', sublabel: 'Some issues need attention' }
    : { bg: 'bg-red-50', border: 'border-red-300', text: 'text-red-700', ring: 'ring-red-200', label: 'Needs urgent attention', sublabel: 'Critical issues found' };

  return (
    <div className="flex flex-col items-center">
      <div className={`${config.bg} ${config.border} border-2 rounded-2xl px-10 py-8 text-center ring-4 ${config.ring} ring-offset-2`}>
        <div className={`text-8xl font-black ${config.text} mb-2 leading-none`}>{score}</div>
        <div className={`text-base font-bold ${config.text} mb-1`}>{config.label}</div>
        <div className="text-slate-500 text-sm">{config.sublabel}</div>
      </div>
    </div>
  );
}

function SummaryBar({ critical, warnings, passed }: { critical: number; warnings: number; passed: number }) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-3 mt-5">
      <span className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-bold ${
        critical > 0 ? 'bg-red-100 text-red-700 border border-red-200' : 'bg-slate-100 text-slate-400 border border-slate-200'
      }`}>
        🔴 {critical} critical
      </span>
      <span className="text-slate-300 text-lg select-none">·</span>
      <span className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-bold ${
        warnings > 0 ? 'bg-amber-100 text-amber-700 border border-amber-200' : 'bg-slate-100 text-slate-400 border border-slate-200'
      }`}>
        🟡 {warnings} warnings
      </span>
      <span className="text-slate-300 text-lg select-none">·</span>
      <span className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-bold ${
        passed > 0 ? 'bg-green-100 text-green-700 border border-green-200' : 'bg-slate-100 text-slate-400 border border-slate-200'
      }`}>
        🟢 {passed} passed
      </span>
    </div>
  );
}

function CheckCard({
  check,
  onFixClick,
}: {
  check: ScanCheck;
  onFixClick: (check: ScanCheck, copy: typeof checkCopy[string]) => void;
}) {
  const sv = severityLabels[check.status];

  // Get human-friendly copy
  const copyKey = (() => {
    if (check.id === 'ssl') return check.status === 'pass' ? 'ssl-pass' : 'ssl-critical';
    if (check.id.startsWith('header-')) {
      const hKey = check.id.replace('header-', 'header-');
      return `${hKey}-${check.status === 'pass' ? 'pass' : 'warning'}`;
    }
    if (check.id === 'cors') return check.status === 'pass' ? 'cors-pass' : 'cors-warning';
    if (check.id === 'url-discovery') return 'url-discovery-pass';
    if (check.id.startsWith('exposure-')) {
      const path = check.value || '';
      if (path === '/.env') return 'exposure-env';
      if (path === '/.env.local') return 'exposure--env-local';
      if (path === '/.env.production') return 'exposure--env-production';
      if (path === '/.git/config') return 'exposure--git-config';
      if (path === '/package.json') return 'exposure--package-json';
      if (path === '/wp-admin') return 'exposure--wp-admin';
    }
    if (check.id.startsWith('secret-')) {
      if (check.id.includes('openai')) return 'secrets-openai-api-key';
      if (check.id.includes('stripe-live')) return 'secrets-stripe-live-key';
      if (check.id.includes('stripe-test')) return 'secrets-stripe-test-key';
      if (check.id.includes('google')) return 'secrets-google-api-key';
      if (check.id.includes('supabase-service-role')) return 'secrets-supabase-service-role-key';
      if (check.id.includes('supabase-url')) return 'secrets-supabase-url';
      if (check.id.includes('supabase-jwt')) return 'secrets-supabase-jwt';
      if (check.id.includes('next-public')) return 'secrets-next-public-secret';
    }
    if (check.id === 'supabase-data-exposure') return 'supabase-data-exposure';
    return '';
  })();

  const copy = copyKey && checkCopy[copyKey] ? checkCopy[copyKey] : null;
  const headline = copy?.headline || check.name;
  const plainEnglish = copy?.plainEnglish || check.detail;
  const hasFixPrompt = !!(copy?.fixPrompt);

  return (
    <div className={`border rounded-xl p-5 ${sv.bg} ${sv.border}`}>
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 mt-1">
          <span className="text-2xl">{sv.emoji}</span>
        </div>
        <div className="flex-1 min-w-0">
          {/* Technical name — small, secondary */}
          <div className="mb-2">
            <span className="text-xs text-slate-400 font-mono">{check.name}</span>
          </div>

          {/* Plain-English headline — BIG and bold */}
          <h3 className="font-extrabold text-slate-900 text-lg sm:text-xl mb-3 leading-snug">
            {headline}
          </h3>

          {/* 5-year-old explanation — softer color */}
          <p className="text-slate-500 text-sm leading-relaxed mb-4">{plainEnglish}</p>

          {/* Value found */}
          {check.value && check.status !== 'pass' && check.status !== 'info' && (
            <div className="mb-4">
              <span className="text-xs text-slate-400 mr-2">Found:</span>
              <span className="url-path">{check.value}</span>
            </div>
          )}

          {/* Severity label + fix button */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${sv.color} ${sv.bg} ${sv.border}`}>
              {sv.label}
            </span>
            {hasFixPrompt && (
              <button
                onClick={() => copy && onFixClick(check, copy)}
                className="text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 active:bg-orange-700 px-4 py-1.5 rounded-full transition-colors flex items-center gap-2 shadow-sm"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 20h9"/>
                  <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
                </svg>
                Get fix prompt
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ExposedDataCard({ item }: { item: ExposedDataItem }) {
  const [expandedTable, setExpandedTable] = useState<string | null>(null);

  const borderColor = item.severity === 'critical' ? 'border-red-200 bg-red-50' : 'border-amber-200 bg-amber-50';
  const badgeColor = item.severity === 'critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700';
  const emoji = item.kind === 'database' ? '🗄️' : item.kind === 'secret' ? '🔑' : '📄';

  // For database kind, initialise first table expanded
  const tables = item.dataLeaks?.tables.filter(t => t.sampleRows.length > 0) ?? [];
  const activeTable = expandedTable ?? (tables.length > 0 ? tables[0].name : null);

  return (
    <div className={`border-2 rounded-xl overflow-hidden ${borderColor}`}>
      {/* Card header */}
      <div className="px-5 py-4 flex items-start gap-3">
        <span className="text-2xl flex-shrink-0">{emoji}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="font-bold text-slate-900">{item.label}</span>
            <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${badgeColor}`}>
              {item.severity === 'critical' ? '🔴 Critical' : '🟡 Warning'}
            </span>
          </div>
          <p className="text-sm text-slate-600 leading-relaxed">{item.description}</p>
          {item.preview && (
            <div className="mt-2">
              <span className="text-xs text-slate-400 mr-1">Found:</span>
              <span className="font-mono text-xs bg-white border border-slate-200 px-2 py-0.5 rounded text-slate-700">{item.preview}</span>
            </div>
          )}
        </div>
      </div>

      {/* Database: full breakdown of accessible + blocked tables */}
      {item.kind === 'database' && item.dataLeaks && (
        <div className="border-t border-red-200">
          {/* "Because your token is exposed" context bar */}
          <div className="px-4 py-3 bg-red-100 border-b border-red-200">
            <p className="text-xs text-red-900 font-semibold mb-1">
              Because your token is exposed in your JavaScript, anyone can run this:
            </p>
            <code className="text-xs bg-red-50 border border-red-200 rounded px-2 py-1 block text-red-800 font-mono overflow-x-auto">
              fetch(&apos;{item.dataLeaks.supabaseUrl}/rest/v1/[table]&apos;, {`{ headers: { apikey: '${item.dataLeaks.keyPreview}' } }`})
            </code>
          </div>

          {/* Table tabs — all accessible tables */}
          {item.dataLeaks.tables.length > 0 && (
            <>
              <div className="flex border-b border-slate-200 bg-white overflow-x-auto">
                {item.dataLeaks.tables.map(table => {
                  const hasData = table.sampleRows.length > 0;
                  return (
                    <button
                      key={table.name}
                      onClick={() => setExpandedTable(table.name)}
                      className={`px-4 py-2.5 text-sm font-semibold whitespace-nowrap border-b-2 transition-colors flex items-center gap-2 ${
                        activeTable === table.name
                          ? 'border-red-500 text-red-700 bg-red-50'
                          : 'border-transparent text-slate-500 hover:text-slate-700'
                      }`}
                    >
                      <span>{hasData ? '🔴' : '🟡'}</span>
                      {table.name}
                      {table.totalRows !== undefined && (
                        <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${
                          hasData ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500'
                        }`}>
                          {table.totalRows.toLocaleString()} rows
                        </span>
                      )}
                    </button>
                  );
                })}
                {/* Protected tables indicator */}
                {item.dataLeaks.blockedTables?.length > 0 && (
                  <div className="px-4 py-2.5 text-xs text-slate-400 whitespace-nowrap flex items-center gap-1">
                    🟢 {item.dataLeaks.blockedTables.length} protected by RLS
                  </div>
                )}
              </div>

              {/* Active table content */}
              {item.dataLeaks.tables.map(table => activeTable === table.name && (
                <div key={table.name}>
                  {table.sampleRows.length > 0 ? (
                    <>
                      <div className="px-4 py-2 bg-red-50 border-b border-red-100 text-xs text-red-700">
                        <strong>Live data from your database</strong> — queried with your public anon key. Emails partially redacted.
                        {table.totalRows !== undefined && table.totalRows > 3 && (
                          <> Showing 3 of {table.totalRows.toLocaleString()} rows.</>
                        )}
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="bg-slate-50 border-b border-slate-100">
                              {table.columns.map(col => (
                                <th key={col} className="px-4 py-2.5 text-left text-xs font-bold text-slate-500 uppercase tracking-wider whitespace-nowrap font-mono">
                                  {col}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-50 bg-white">
                            {table.sampleRows.map((row, ri) => (
                              <tr key={ri} className="hover:bg-slate-50">
                                {table.columns.map(col => {
                                  const val = redactValue(col, row[col]);
                                  return (
                                    <td key={col} className={`px-4 py-2.5 whitespace-nowrap font-mono text-xs ${val === '●●●●●●●●' ? 'text-slate-300' : 'text-slate-700'}`}>
                                      {val}
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  ) : (
                    <div className="px-4 py-4 bg-amber-50 border-b border-amber-100">
                      <p className="text-xs text-amber-800 font-semibold mb-2">
                        Table is accessible but returned 0 rows (may be empty or filtered by RLS).
                        Schema is still visible:
                      </p>
                      {table.columns.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {table.columns.map(col => (
                            <span key={col} className="font-mono text-xs bg-white border border-amber-200 px-2 py-0.5 rounded text-amber-800">
                              {col}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  <div className="px-4 py-2.5 bg-white border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
                    <span className="font-mono text-slate-400">{item.dataLeaks?.supabaseUrl}/rest/v1/{table.name}</span>
                    <a href="https://supabase.com/docs/guides/auth/row-level-security" target="_blank" rel="noopener noreferrer"
                      className="text-orange-600 font-semibold hover:text-orange-700 whitespace-nowrap ml-4">
                      Fix with RLS →
                    </a>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function DiscoveredUrlsSection({ urls }: { urls: string[] }) {
  const [showAll, setShowAll] = useState(false);

  if (urls.length === 0) {
    return (
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center text-slate-500">
        No URLs discovered. The site may not have a sitemap or public links.
      </div>
    );
  }

  // Derive origin from first URL for display
  let origin = '';
  try { origin = new URL(urls[0]).origin; } catch {}

  // Sort: warnings/critical first, then alpha
  const sorted = [...urls].sort((a, b) => {
    const ca = classifyUrl(a);
    const cb = classifyUrl(b);
    const order = { critical: 0, warning: 1, info: 2 };
    return order[ca.severity] - order[cb.severity];
  });

  const toShow = showAll ? sorted : sorted.slice(0, 15);

  return (
    <div>
      {/* Header with origin */}
      {origin && (
        <div className="px-4 py-2.5 bg-slate-50 border border-slate-200 border-b-0 rounded-t-xl flex items-center gap-2 text-xs text-slate-500">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          <span className="font-mono font-medium text-slate-700">{origin}</span>
          <span className="ml-auto">{urls.length} pages indexed</span>
        </div>
      )}

      {/* URL rows */}
      <div className={`border border-slate-200 ${origin ? 'rounded-b-xl' : 'rounded-xl'} overflow-hidden divide-y divide-slate-100`}>
        {toShow.map((url, i) => {
          const classified = classifyUrl(url);
          let path = '/';
          try { path = new URL(url).pathname || '/'; } catch {}

          // Indent sub-paths visually
          const depth = (path.match(/\//g) || []).length - 1;
          const paddingLeft = Math.min(depth, 3) * 16;

          const rowBg = classified.severity === 'critical'
            ? 'bg-red-50'
            : classified.severity === 'warning'
            ? 'bg-amber-50'
            : i % 2 === 0 ? 'bg-white' : 'bg-slate-50/50';

          return (
            <div key={i} className={`flex items-center gap-3 px-4 py-2.5 ${rowBg} hover:bg-slate-100 transition-colors group`}
              style={{ paddingLeft: `${16 + paddingLeft}px` }}>
              <span className="text-sm flex-shrink-0 w-5 text-center">{classified.emoji}</span>

              {/* Path — monospace, tree-style */}
              <div className="flex-1 min-w-0 flex items-baseline gap-2">
                <span className="font-mono text-sm text-slate-800 truncate max-w-[200px] sm:max-w-sm">
                  {path === '/' ? '/' : path}
                </span>
                <span className="text-xs text-slate-400 truncate hidden sm:block">{classified.label}</span>
              </div>

              {/* Full URL on hover — external link */}
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-300 hover:text-orange-500 transition-colors flex-shrink-0 opacity-0 group-hover:opacity-100 flex items-center gap-1"
                title={url}
              >
                <span className="text-xs text-slate-400 font-mono hidden sm:block max-w-[180px] truncate">{url}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                  <polyline points="15,3 21,3 21,9"/>
                  <line x1="10" y1="14" x2="21" y2="3"/>
                </svg>
              </a>

              {/* Severity badge for warnings/critical */}
              {classified.severity !== 'info' && (
                <span className={`text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${
                  classified.severity === 'critical'
                    ? 'bg-red-100 text-red-700'
                    : 'bg-amber-100 text-amber-700'
                }`}>
                  {classified.severity === 'critical' ? '⚠️ Review' : '👀 Check'}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {urls.length > 15 && (
        <button
          onClick={() => setShowAll(v => !v)}
          className="w-full py-3 text-sm text-slate-500 hover:text-slate-700 border border-t-0 border-slate-200 rounded-b-xl transition-colors bg-white"
        >
          {showAll ? '↑ Show fewer' : `↓ Show all ${urls.length} pages`}
        </button>
      )}
    </div>
  );
}

// Redact sensitive values for display
function redactValue(col: string, value: unknown): string {
  if (value === null || value === undefined) return '—';
  const str = String(value);
  const lowerCol = col.toLowerCase();

  // Password / hash columns — always fully redact
  if (lowerCol.includes('password') || lowerCol.includes('hash') || lowerCol.includes('secret') || lowerCol.includes('token')) {
    return '●●●●●●●●';
  }

  // Email addresses — partial redact
  if (typeof value === 'string' && value.includes('@') && value.includes('.')) {
    const parts = value.split('@');
    const name = parts[0];
    const domain = parts[1];
    return `${name.slice(0, 2)}${'*'.repeat(Math.max(2, name.length - 2))}@${domain}`;
  }

  // UUIDs / long ID strings — truncate
  if (typeof value === 'string' && str.length > 20 && (lowerCol === 'id' || lowerCol.endsWith('_id') || lowerCol.includes('uuid'))) {
    return str.slice(0, 8) + '…';
  }

  // Long strings — truncate
  if (typeof value === 'string' && str.length > 40) {
    return str.slice(0, 38) + '…';
  }

  return str;
}


function LoadingTerminal({ targetUrl }: { targetUrl: string }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      setCompletedSteps(prev => {
        if (prev.length < TERMINAL_STEPS.length) {
          return [...prev, prev.length];
        }
        return prev;
      });
      setStepIndex(prev => {
        if (prev < TERMINAL_STEPS.length - 1) return prev + 1;
        clearInterval(interval);
        return prev;
      });
    }, 1300);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-white flex flex-col items-center justify-center px-6 py-20">
      <div className="max-w-xl w-full">
        <div className="text-center mb-8">
          <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center mx-auto mb-4">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-slate-900 mb-2">Scanning your app…</h1>
          <p className="text-slate-500 text-sm font-mono truncate max-w-sm mx-auto">{targetUrl}</p>
        </div>

        {/* Progress bar */}
        <div className="h-2 bg-slate-100 rounded-full mb-6 overflow-hidden">
          <div
            className="h-full bg-orange-400 rounded-full transition-all duration-700"
            style={{ width: `${((completedSteps.length) / TERMINAL_STEPS.length) * 100}%` }}
          />
        </div>

        {/* Terminal-style steps */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 space-y-2.5">
          {TERMINAL_STEPS.map((step, i) => {
            const isDone = completedSteps.includes(i);
            const isCurrent = i === stepIndex && !isDone;
            return (
              <div key={i} className={`flex items-center gap-3 text-sm transition-opacity duration-300 ${i > stepIndex ? 'opacity-25' : 'opacity-100'}`}>
                {isDone ? (
                  <span className="text-green-500 flex-shrink-0">✓</span>
                ) : isCurrent ? (
                  <span className="flex-shrink-0 w-4 h-4">
                    <svg className="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2.5">
                      <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                    </svg>
                  </span>
                ) : (
                  <span className="text-slate-300 flex-shrink-0 text-xs">○</span>
                )}
                <span className={isDone ? 'text-slate-600' : isCurrent ? 'text-slate-900 font-medium' : 'text-slate-400'}>
                  {step}
                </span>
              </div>
            );
          })}
        </div>

        <p className="text-center text-xs text-slate-400 mt-4">
          This takes about 15–30 seconds. We&apos;re making standard HTTP requests only — your app is safe.
        </p>
      </div>
    </div>
  );
}

function ScanPageInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const rawUrl = searchParams.get('url') || '';

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'pages' | 'data' | 'risks'>('risks');
  const [modal, setModal] = useState<{
    isOpen: boolean;
    check: ScanCheck | null;
    copy: typeof checkCopy[string] | null;
  }>({ isOpen: false, check: null, copy: null });
  const [shared, setShared] = useState(false);

  const runScan = useCallback(async () => {
    if (!rawUrl) {
      setError('No URL provided.');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `Scan failed (${res.status})`);
      }

      const data = await res.json();
      setReport(data);
      // Auto-switch to Data tab if there are leaks, otherwise Risks
      if (data.dataLeaks?.openTables > 0 || data.checks?.some((c: ScanCheck) => c.id.startsWith('secret-') && c.status === 'critical')) {
        setActiveTab('data');
      } else {
        setActiveTab('risks');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [rawUrl]);

  useEffect(() => {
    runScan();
  }, [runScan]);

  function handleShare() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setShared(true);
      setTimeout(() => setShared(false), 2500);
    });
  }

  function handleFixClick(check: ScanCheck, copy: typeof checkCopy[string]) {
    setModal({ isOpen: true, check, copy });
  }

  if (loading) {
    return <LoadingTerminal targetUrl={rawUrl} />;
  }

  if (error) {
    return (
      <div className="min-h-screen bg-white flex flex-col items-center justify-center px-6 py-20 text-center">
        <div className="text-5xl mb-4">😕</div>
        <h1 className="text-2xl font-bold text-slate-900 mb-3">Scan failed</h1>
        <p className="text-slate-500 max-w-md mb-6">{error}</p>
        <div className="flex gap-3">
          <button
            onClick={() => router.push('/')}
            className="px-5 py-2.5 border border-slate-200 rounded-xl text-slate-700 hover:bg-slate-50 transition-colors text-sm font-medium"
          >
            ← Back home
          </button>
          <button
            onClick={runScan}
            className="px-5 py-2.5 bg-orange-500 text-white rounded-xl hover:bg-orange-600 transition-colors text-sm font-medium"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const criticalChecks = report.checks.filter(c => c.status === 'critical');
  const warningChecks = report.checks.filter(c => c.status === 'warning');
  const passChecks = report.checks.filter(c => c.status === 'pass');

  // Build unified exposed data items from checks + dataLeaks
  const exposedItems: ExposedDataItem[] = [];

  // Pull exposed files/paths from checks
  for (const check of report.checks) {
    if (check.id.startsWith('exposure-') && check.status !== 'pass' && check.value) {
      exposedItems.push({
        kind: 'file',
        label: check.value,
        description: check.detail,
        severity: check.status as 'critical' | 'warning',
      });
    }
    if (check.id.startsWith('secret-') && check.status !== 'pass') {
      exposedItems.push({
        kind: 'secret',
        label: check.name,
        description: check.detail,
        preview: check.value,
        severity: check.status as 'critical' | 'warning',
      });
    }
  }

  // Pull Supabase live table data — show if ANY tables are accessible
  if (report.dataLeaks && (report.dataLeaks.openTables > 0 || report.dataLeaks.tables.length > 0)) {
    const dl = report.dataLeaks;
    const accessible = dl.tables.length;
    const withData = dl.openTables;
    const blocked = dl.blockedTables?.length ?? 0;
    exposedItems.push({
      kind: 'database',
      label: `Supabase database accessible via exposed token`,
      description: `${accessible} table${accessible !== 1 ? 's' : ''} queryable with your public anon key.${withData > 0 ? ` ${withData} returning live rows.` : ''} ${blocked > 0 ? `${blocked} protected by RLS.` : ''}`,
      severity: 'critical',
      dataLeaks: report.dataLeaks,
    });
  }

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Nav */}
      <nav className="bg-white border-b border-slate-100 px-6 py-4 sticky top-0 z-10">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <button
            onClick={() => router.push('/')}
            className="flex items-center gap-2 text-slate-600 hover:text-slate-900 transition-colors text-sm font-medium"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="m15 18-6-6 6-6"/>
            </svg>
            VibeScan
          </button>
          <div className="flex items-center gap-3">
            <button
              onClick={handleShare}
              className="flex items-center gap-2 text-sm px-4 py-2 border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors text-slate-600 font-medium"
            >
              {shared ? (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                    <polyline points="20,6 9,17 4,12"/>
                  </svg>
                  <span className="text-green-600">Link copied!</span>
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/>
                    <polyline points="16,6 12,2 8,6"/>
                    <line x1="12" y1="2" x2="12" y2="15"/>
                  </svg>
                  Share report
                </>
              )}
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 py-6 space-y-6">

        {/* ── Score card ── */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8">
          <p className="text-xs text-slate-400 font-semibold uppercase tracking-widest mb-1">Security Report</p>
          <h1 className="text-lg sm:text-xl font-bold text-slate-900 mb-0.5 break-all font-mono">{report.url}</h1>
          <p className="text-slate-400 text-xs mb-6">
            Scanned {new Date(report.scannedAt).toLocaleString()} · Passive scan only
          </p>
          <div className="flex flex-col items-center mb-2">
            <ScoreBadge score={report.score} />
            <SummaryBar
              critical={report.summary.critical}
              warnings={report.summary.warnings}
              passed={report.summary.passed}
            />
          </div>
        </div>

        {/* ── Tab bar ── */}
        <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden">
          <div className="flex border-b border-slate-100">
            {/* Pages tab */}
            <button
              onClick={() => setActiveTab('pages')}
              className={`flex-1 flex flex-col sm:flex-row items-center justify-center gap-1 sm:gap-2 px-3 py-4 text-sm font-semibold transition-colors border-b-2 ${
                activeTab === 'pages'
                  ? 'border-blue-500 text-blue-700 bg-blue-50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
              }`}
            >
              <span className="text-xl">🗺️</span>
              <span>Pages</span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                activeTab === 'pages' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-500'
              }`}>
                {report.discoveredUrls.length}
              </span>
            </button>

            {/* Data tab */}
            <button
              onClick={() => setActiveTab('data')}
              className={`flex-1 flex flex-col sm:flex-row items-center justify-center gap-1 sm:gap-2 px-3 py-4 text-sm font-semibold transition-colors border-b-2 ${
                activeTab === 'data'
                  ? 'border-red-500 text-red-700 bg-red-50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
              }`}
            >
              <span className="text-xl">🔓</span>
              <span>Data Leaks</span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                exposedItems.length > 0
                  ? activeTab === 'data' ? 'bg-red-100 text-red-700' : 'bg-red-100 text-red-600'
                  : activeTab === 'data' ? 'bg-green-100 text-green-700' : 'bg-green-100 text-green-600'
              }`}>
                {exposedItems.length > 0 ? `${exposedItems.length} found` : '✓ Clean'}
              </span>
            </button>

            {/* Risks tab */}
            <button
              onClick={() => setActiveTab('risks')}
              className={`flex-1 flex flex-col sm:flex-row items-center justify-center gap-1 sm:gap-2 px-3 py-4 text-sm font-semibold transition-colors border-b-2 ${
                activeTab === 'risks'
                  ? 'border-orange-500 text-orange-700 bg-orange-50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
              }`}
            >
              <span className="text-xl">🛡️</span>
              <span>Risks</span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                report.summary.critical > 0
                  ? activeTab === 'risks' ? 'bg-red-100 text-red-700' : 'bg-red-100 text-red-600'
                  : activeTab === 'risks' ? 'bg-amber-100 text-amber-700' : 'bg-amber-100 text-amber-600'
              }`}>
                {report.summary.critical > 0 ? `${report.summary.critical} critical` : `${report.summary.warnings} warnings`}
              </span>
            </button>
          </div>

          {/* ── Tab: Pages ── */}
          {activeTab === 'pages' && (
            <div className="p-4 sm:p-6">
              <p className="text-slate-500 text-sm mb-4">
                Every URL found via sitemap, robots.txt, and JavaScript bundle route extraction.
                Check that each one should be publicly reachable.
              </p>
              <DiscoveredUrlsSection urls={report.discoveredUrls} />
            </div>
          )}

          {/* ── Tab: Data Leaks ── */}
          {activeTab === 'data' && (
            <div className="p-4 sm:p-6">
              <p className="text-slate-500 text-sm mb-4">
                Credentials, secrets, and live database rows visible to anyone right now.
              </p>
              {exposedItems.length === 0 ? (
                <div className="bg-green-50 border border-green-200 rounded-xl p-6 flex items-center gap-4">
                  <span className="text-3xl">✅</span>
                  <div>
                    <p className="font-bold text-green-800">No data leaks detected</p>
                    <p className="text-green-700 text-sm mt-0.5">
                      No exposed credentials, secrets, or open database tables found.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {exposedItems.map((item, i) => (
                    <ExposedDataCard key={i} item={item} />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── Tab: Risks ── */}
          {activeTab === 'risks' && (
            <div className="p-4 sm:p-6 space-y-6">
              {criticalChecks.length === 0 && warningChecks.length === 0 && passChecks.length === 0 && (
                <p className="text-slate-500 text-sm">No security checks available.</p>
              )}
              {criticalChecks.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-base">🔴</span>
                    <h3 className="font-bold text-slate-800">Urgent — fix these today</h3>
                    <span className="bg-red-100 text-red-700 text-xs font-bold px-2 py-0.5 rounded-full">{criticalChecks.length}</span>
                  </div>
                  <div className="space-y-3">
                    {criticalChecks.map(check => (
                      <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
                    ))}
                  </div>
                </div>
              )}
              {warningChecks.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-base">🟡</span>
                    <h3 className="font-bold text-slate-800">Worth fixing soon</h3>
                    <span className="bg-amber-100 text-amber-700 text-xs font-bold px-2 py-0.5 rounded-full">{warningChecks.length}</span>
                  </div>
                  <div className="space-y-3">
                    {warningChecks.map(check => (
                      <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
                    ))}
                  </div>
                </div>
              )}
              {passChecks.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-base">🟢</span>
                    <h3 className="font-bold text-slate-800">Checks you passed</h3>
                    <span className="bg-green-100 text-green-700 text-xs font-bold px-2 py-0.5 rounded-full">{passChecks.length}</span>
                  </div>
                  <div className="space-y-3">
                    {passChecks.map(check => (
                      <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* CTA */}
        <section className="bg-orange-50 border border-orange-100 rounded-2xl p-8 text-center">
          <h2 className="text-2xl font-bold text-slate-900 mb-3">
            Need help fixing these?
          </h2>
          <p className="text-slate-600 mb-6 max-w-lg mx-auto leading-relaxed">
            Creative Digital Group builds secure, production-ready apps. We can review your scan results,
            fix the issues found, and help you ship with confidence.
          </p>
          <a
            href="https://creativedigital.group"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-8 py-3.5 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors text-base"
          >
            Talk to Creative Digital Group →
          </a>
        </section>

        {/* Disclaimer */}
        <div className="text-center pb-4">
          <p className="text-xs text-slate-400 leading-relaxed max-w-xl mx-auto">
            VibeScan uses passive HTTP requests only — we never modify, stress-test, or access protected areas of your app.
            Results reflect publicly accessible information only. You are responsible for verifying and applying any fixes.
          </p>
        </div>
      </main>

      {/* Fix Prompt Modal */}
      <FixPromptModal
        isOpen={modal.isOpen}
        onClose={() => setModal(m => ({ ...m, isOpen: false }))}
        checkName={modal.check?.name || ''}
        headline={modal.copy?.headline || ''}
        prompt={modal.copy?.fixPrompt || ''}
        warning={modal.copy?.fixPromptWarning || 'Test your app after applying this change.'}
      />
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="text-slate-400">Loading…</div>
      </div>
    }>
      <ScanPageInner />
    </Suspense>
  );
}
