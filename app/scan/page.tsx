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

interface ScanReport {
  url: string;
  scannedAt: string;
  score: number;
  summary: { critical: number; warnings: number; passed: number };
  discoveredUrls: string[];
  checks: ScanCheck[];
}

const TERMINAL_STEPS = [
  '🔍 Resolving domain...',
  '🗺️  Fetching sitemap.xml...',
  '🤖 Reading robots.txt...',
  '🔗 Crawling homepage links...',
  '🚪 Checking for exposed files (.env, .git)...',
  '🛡️  Inspecting security headers...',
  '🔑 Scanning JavaScript bundles for secrets...',
  '🌐 Testing CORS policy...',
  '🔒 Verifying SSL / HTTPS...',
  '📊 Calculating your security score...',
];

function ScoreBadge({ score }: { score: number }) {
  const isGood = score >= 70;
  const isMid = score >= 40 && score < 70;

  const config = isGood
    ? { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700', label: "You're in good shape", sublabel: 'A few things to review' }
    : isMid
    ? { bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-700', label: 'Room for improvement', sublabel: 'Some issues need attention' }
    : { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700', label: 'Needs urgent attention', sublabel: 'Critical issues found' };

  return (
    <div className={`${config.bg} ${config.border} border-2 rounded-2xl p-8 text-center`}>
      <div className={`text-7xl font-bold ${config.text} mb-2`}>{score}</div>
      <div className={`text-lg font-semibold ${config.text} mb-1`}>{config.label}</div>
      <div className="text-slate-500 text-sm">{config.sublabel}</div>
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
    // Map check IDs to copy keys
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
      if (check.id.includes('supabase-url')) return 'secrets-supabase-url';
      if (check.id.includes('supabase-jwt')) return 'secrets-supabase-jwt';
      if (check.id.includes('next-public')) return 'secrets-next-public-secret';
    }
    return '';
  })();

  const copy = copyKey && checkCopy[copyKey] ? checkCopy[copyKey] : null;
  const headline = copy?.headline || check.name;
  const plainEnglish = copy?.plainEnglish || check.detail;
  const hasFixPrompt = !!(copy?.fixPrompt);

  const categoryLabel: Record<string, string> = {
    pages: 'Page Discovery',
    headers: 'Security Headers',
    secrets: 'Exposed Secrets',
    exposure: 'File Exposure',
    ssl: 'SSL / HTTPS',
  };

  return (
    <div className={`border rounded-xl p-5 ${sv.bg} ${sv.border}`}>
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 mt-0.5">
          <span className="text-2xl">{sv.emoji}</span>
        </div>
        <div className="flex-1 min-w-0">
          {/* Category + technical name */}
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wide">
              {categoryLabel[check.category] || check.category}
            </span>
            <span className="text-slate-200">·</span>
            <span className="text-xs text-slate-400 font-mono">{check.name}</span>
          </div>

          {/* Plain-English headline */}
          <h3 className={`font-semibold text-slate-900 text-base mb-2 leading-snug`}>
            {headline}
          </h3>

          {/* 5-year-old explanation */}
          <p className="text-slate-600 text-sm leading-relaxed mb-3">{plainEnglish}</p>

          {/* Value found */}
          {check.value && check.status !== 'pass' && check.status !== 'info' && (
            <div className="mb-3">
              <span className="text-xs text-slate-400 mr-2">Found:</span>
              <span className="url-path">{check.value}</span>
            </div>
          )}

          {/* Severity label + fix button */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${sv.color} ${sv.bg} ${sv.border}`}>
              {sv.label}
            </span>
            {hasFixPrompt && (
              <button
                onClick={() => copy && onFixClick(check, copy)}
                className="text-xs font-semibold text-orange-600 hover:text-orange-700 border border-orange-200 hover:border-orange-300 bg-white hover:bg-orange-50 px-3 py-1 rounded-full transition-colors flex items-center gap-1.5"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
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

function DiscoveredUrlsSection({ urls }: { urls: string[] }) {
  const [showAll, setShowAll] = useState(false);
  const display = showAll ? urls : urls.slice(0, 10);

  if (urls.length === 0) {
    return (
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center text-slate-500">
        No URLs discovered. The site may not have a sitemap or public links.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {display.map((url, i) => {
        const classified = classifyUrl(url);
        let path = url;
        try { path = new URL(url).pathname || url; } catch {}

        const rowBg = classified.severity === 'critical'
          ? 'bg-red-50 border-red-100'
          : classified.severity === 'warning'
          ? 'bg-amber-50 border-amber-100'
          : 'bg-white border-slate-100';

        return (
          <div key={i} className={`flex items-center gap-3 px-4 py-3 border rounded-lg ${rowBg}`}>
            <span className="text-base flex-shrink-0">{classified.emoji}</span>
            <span className="url-path text-slate-700 flex-shrink-0 max-w-xs truncate">{path}</span>
            <span className="text-slate-400 text-sm flex-1 min-w-0">{classified.label}</span>
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-slate-500 transition-colors flex-shrink-0"
              aria-label={`Open ${url}`}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15,3 21,3 21,9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </a>
          </div>
        );
      })}
      {urls.length > 10 && (
        <button
          onClick={() => setShowAll(v => !v)}
          className="w-full py-2 text-sm text-slate-500 hover:text-slate-700 border border-dashed border-slate-200 rounded-lg transition-colors"
        >
          {showAll ? 'Show less ↑' : `Show all ${urls.length} pages ↓`}
        </button>
      )}
    </div>
  );
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
          This takes about 15 seconds. We&apos;re making standard HTTP requests only — your app is safe.
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

      <main className="max-w-5xl mx-auto px-6 py-10 space-y-10">
        {/* Header */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8">
          <p className="text-xs text-slate-400 font-medium uppercase tracking-wide mb-1">Security Report</p>
          <h1 className="text-2xl font-bold text-slate-900 mb-1 break-all font-mono">{report.url}</h1>
          <p className="text-slate-400 text-sm mb-6">
            Scanned {new Date(report.scannedAt).toLocaleString()} · Passive scan only
          </p>

          {/* Score + Summary grid */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="sm:col-span-1">
              <ScoreBadge score={report.score} />
            </div>
            <div className="sm:col-span-3 grid grid-cols-3 gap-4">
              <div className="bg-red-50 border border-red-100 rounded-xl p-4 text-center">
                <div className="text-4xl font-bold text-red-600 mb-1">{report.summary.critical}</div>
                <div className="text-sm font-medium text-red-700">🔴 Urgent</div>
                <div className="text-xs text-red-500 mt-0.5">Fix today</div>
              </div>
              <div className="bg-amber-50 border border-amber-100 rounded-xl p-4 text-center">
                <div className="text-4xl font-bold text-amber-600 mb-1">{report.summary.warnings}</div>
                <div className="text-sm font-medium text-amber-700">🟡 Warnings</div>
                <div className="text-xs text-amber-500 mt-0.5">Fix soon</div>
              </div>
              <div className="bg-green-50 border border-green-100 rounded-xl p-4 text-center">
                <div className="text-4xl font-bold text-green-600 mb-1">{report.summary.passed}</div>
                <div className="text-sm font-medium text-green-700">🟢 Passed</div>
                <div className="text-xs text-green-500 mt-0.5">Good shape</div>
              </div>
            </div>
          </div>
        </div>

        {/* Critical findings */}
        {criticalChecks.length > 0 && (
          <section>
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xl">🔴</span>
              <h2 className="text-lg font-bold text-slate-900">Urgent — fix these today</h2>
              <span className="bg-red-100 text-red-700 text-xs font-bold px-2 py-0.5 rounded-full">{criticalChecks.length}</span>
            </div>
            <div className="space-y-3">
              {criticalChecks.map(check => (
                <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
              ))}
            </div>
          </section>
        )}

        {/* Warnings */}
        {warningChecks.length > 0 && (
          <section>
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xl">🟡</span>
              <h2 className="text-lg font-bold text-slate-900">Worth fixing soon</h2>
              <span className="bg-amber-100 text-amber-700 text-xs font-bold px-2 py-0.5 rounded-full">{warningChecks.length}</span>
            </div>
            <div className="space-y-3">
              {warningChecks.map(check => (
                <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
              ))}
            </div>
          </section>
        )}

        {/* Discovered URLs */}
        <section>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xl">🗺️</span>
            <h2 className="text-lg font-bold text-slate-900">
              {report.discoveredUrls.length} pages discovered
            </h2>
          </div>
          <p className="text-slate-500 text-sm mb-4">
            These are all the URLs we found by reading your sitemap, robots.txt, and homepage links.
            Some of these might surprise you — especially the ones flagged below.
          </p>
          <div className="bg-white border border-slate-200 rounded-xl p-4">
            <DiscoveredUrlsSection urls={report.discoveredUrls} />
          </div>
        </section>

        {/* Passed checks */}
        {passChecks.length > 0 && (
          <section>
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xl">🟢</span>
              <h2 className="text-lg font-bold text-slate-900">Checks you passed</h2>
              <span className="bg-green-100 text-green-700 text-xs font-bold px-2 py-0.5 rounded-full">{passChecks.length}</span>
            </div>
            <div className="space-y-3">
              {passChecks.map(check => (
                <CheckCard key={check.id} check={check} onFixClick={handleFixClick} />
              ))}
            </div>
          </section>
        )}

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
