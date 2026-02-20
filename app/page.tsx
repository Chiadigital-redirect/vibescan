'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getScanHistory, removeScanFromHistory, ScanHistoryEntry } from '@/lib/scan-history';

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const router = useRouter();

  // Load scan history from localStorage on mount (client-side only)
  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    let normalized = url.trim();
    if (!normalized) {
      setError('Please enter a URL to scan.');
      return;
    }
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized;
    }
    try {
      new URL(normalized);
    } catch {
      setError("That doesn't look like a valid URL. Try something like: myapp.vercel.app");
      return;
    }

    const encoded = encodeURIComponent(normalized);
    router.push(`/scan?url=${encoded}`);
  }

  function handleRemove(domain: string) {
    removeScanFromHistory(domain);
    setHistory(getScanHistory());
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Nav */}
      <nav className="border-b border-slate-100 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-orange-500 rounded-lg flex items-center justify-center">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <span className="font-semibold text-slate-900 text-lg">VibeScan</span>
          </div>
          <a
            href="https://creativedigital.group"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-slate-500 hover:text-slate-700 transition-colors"
          >
            By Creative Digital Group →
          </a>
        </div>
      </nav>

      {/* Hero */}
      <section className="px-6 pt-16 pb-20 sm:pt-24 sm:pb-28">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col lg:flex-row items-center gap-12 lg:gap-16">
            {/* Left: text + form */}
            <div className="flex-1 text-center lg:text-left">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 bg-orange-50 border border-orange-200 rounded-full px-4 py-1.5 mb-8">
                <span className="w-2 h-2 bg-orange-500 rounded-full animate-pulse"></span>
                <span className="text-orange-600 text-sm font-medium">Built with Lovable, Bolt, Cursor, or V0? You need this.</span>
              </div>

              <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold text-slate-900 leading-[1.08] tracking-tight mb-6">
                Is your app
                <br />
                <span className="text-orange-500">leaking?</span>
              </h1>

              <p className="text-xl text-slate-500 leading-relaxed mb-8 max-w-xl mx-auto lg:mx-0">
                AI tools make building fast — but they often leave security gaps that can expose your users&apos; data,
                your API keys, or your entire source code. VibeScan finds what you missed, in plain English.
              </p>

              {/* Social proof */}
              <div className="flex items-center justify-center lg:justify-start gap-6 mb-10">
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                    <polyline points="20,6 9,17 4,12"/>
                  </svg>
                  <span>Under 30 seconds</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                    <polyline points="20,6 9,17 4,12"/>
                  </svg>
                  <span>No account needed</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                    <polyline points="20,6 9,17 4,12"/>
                  </svg>
                  <span>Free</span>
                </div>
              </div>

              {/* Scan form */}
              <form onSubmit={handleSubmit} className="max-w-xl mx-auto lg:mx-0">
                <div className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="text"
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="myapp.vercel.app"
                    className="flex-1 w-full px-5 py-4 text-lg border-2 border-slate-200 rounded-xl focus:outline-none focus:border-orange-400 transition-colors text-slate-900 placeholder-slate-400 font-mono min-h-[56px]"
                    aria-label="Website URL to scan"
                  />
                  <button
                    type="submit"
                    className="w-full sm:w-auto px-8 py-4 bg-orange-500 hover:bg-orange-600 active:bg-orange-700 text-white font-bold text-lg rounded-xl transition-colors shadow-sm whitespace-nowrap min-h-[56px]"
                  >
                    Scan Now →
                  </button>
                </div>
                {error && (
                  <p className="mt-3 text-red-500 text-sm text-left">{error}</p>
                )}
                <p className="mt-3 text-sm text-slate-400 text-center sm:text-left">
                  Free · No signup required · Passive scan only (we never modify your app)
                </p>
              </form>
            </div>

            {/* Right: Mockup scan result card */}
            <div className="flex-shrink-0 w-full max-w-sm lg:max-w-xs xl:max-w-sm">
              <div className="bg-white border-2 border-slate-100 rounded-2xl shadow-xl overflow-hidden">
                {/* Card header */}
                <div className="bg-slate-50 border-b border-slate-100 px-5 py-3 flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-400"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-400"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-green-400"></div>
                  <span className="ml-2 text-xs text-slate-400 font-mono truncate">myapp.vercel.app — Security Report</span>
                </div>
                {/* Score */}
                <div className="px-5 pt-5 pb-3 border-b border-slate-100 flex items-center justify-between">
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide font-medium mb-0.5">Security Score</p>
                    <p className="text-slate-500 text-xs">2 critical · 3 warnings · 5 passed</p>
                  </div>
                  <div className="w-14 h-14 rounded-xl bg-amber-50 border-2 border-amber-200 flex items-center justify-center">
                    <span className="text-2xl font-bold text-amber-600">62</span>
                  </div>
                </div>
                {/* Check items */}
                <div className="p-4 space-y-2.5">
                  <div className="flex items-start gap-3 bg-red-50 border border-red-100 rounded-lg px-3 py-2.5">
                    <span className="text-base">🔴</span>
                    <div>
                      <p className="text-xs font-bold text-slate-800 leading-snug">Your .env file is public</p>
                      <p className="text-xs text-slate-500">Anyone can read your API keys</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 bg-amber-50 border border-amber-100 rounded-lg px-3 py-2.5">
                    <span className="text-base">🟡</span>
                    <div>
                      <p className="text-xs font-bold text-slate-800 leading-snug">No HTTPS security headers</p>
                      <p className="text-xs text-slate-500">Browser can be tricked into HTTP</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 bg-green-50 border border-green-100 rounded-lg px-3 py-2.5">
                    <span className="text-base">🟢</span>
                    <div>
                      <p className="text-xs font-bold text-slate-800 leading-snug">SSL / HTTPS enabled</p>
                      <p className="text-xs text-slate-500">Traffic is encrypted in transit</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 bg-red-50 border border-red-100 rounded-lg px-3 py-2.5">
                    <span className="text-base">🔴</span>
                    <div>
                      <p className="text-xs font-bold text-slate-800 leading-snug">OpenAI key in JS bundle</p>
                      <p className="text-xs text-slate-500">Rotate immediately — sk-abc123...</p>
                    </div>
                  </div>
                </div>
                <div className="px-4 pb-4">
                  <div className="w-full py-2 bg-orange-500 rounded-lg text-white text-xs font-semibold text-center">
                    Get fix prompts for Cursor / Lovable →
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature cards */}
      <section className="bg-slate-50 border-y border-slate-100 py-16 px-6">
        <div className="max-w-5xl mx-auto">
          <p className="text-center text-slate-500 text-sm font-semibold uppercase tracking-widest mb-12">What VibeScan checks for</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-8">
            {/* Pages Discovered */}
            <div className="bg-white border border-slate-100 rounded-2xl p-7 flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow">
              <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center flex-shrink-0">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/>
                  <path d="m13 13 6 6"/>
                </svg>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-lg mb-2">Pages Discovered</h3>
                <p className="text-slate-500 text-sm leading-relaxed">
                  We map your sitemap, robots.txt, and links to show every page visible to the internet — including the ones you might have forgotten about.
                </p>
              </div>
            </div>

            {/* Security Headers */}
            <div className="bg-white border border-slate-100 rounded-2xl p-7 flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow">
              <div className="w-12 h-12 bg-orange-100 rounded-xl flex items-center justify-center flex-shrink-0">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-lg mb-2">Security Headers</h3>
                <p className="text-slate-500 text-sm leading-relaxed">
                  Six protective settings most AI-generated apps are missing. We explain each one in plain English and give you the exact fix prompt.
                </p>
              </div>
            </div>

            {/* Exposed Secrets */}
            <div className="bg-white border border-slate-100 rounded-2xl p-7 flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow">
              <div className="w-12 h-12 bg-red-100 rounded-xl flex items-center justify-center flex-shrink-0">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="7.5" cy="15.5" r="5.5"/>
                  <path d="m21 2-9.6 9.6"/>
                  <path d="m15.5 7.5 3 3L22 7l-3-3"/>
                </svg>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-lg mb-2">Exposed Secrets</h3>
                <p className="text-slate-500 text-sm leading-relaxed">
                  API keys accidentally bundled into your JavaScript, .env files left public, and Git repos that shouldn&apos;t be accessible to anyone with a browser.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="px-6 py-24">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-slate-900 mb-4">How it works</h2>
            <p className="text-slate-500 text-lg">Three steps. Under 30 seconds. No account needed.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-12">
            {[
              { step: '1', title: 'Enter your URL', desc: "Paste your app's URL — the same one your users visit. No login, no sign-up, no credit card." },
              { step: '2', title: 'We run the checks', desc: 'We make standard HTTP requests to your app — the same requests any browser would make. We never modify, inject, or stress-test your app.' },
              { step: '3', title: 'Read your report', desc: 'Every finding is explained in plain English with a severity rating and a ready-to-use fix prompt for Lovable, Cursor, or ChatGPT.' },
            ].map(({ step, title, desc }) => (
              <div key={step} className="flex flex-col gap-4">
                <div className="w-12 h-12 bg-orange-500 rounded-full flex items-center justify-center text-white font-bold text-xl flex-shrink-0">
                  {step}
                </div>
                <h3 className="font-bold text-slate-900 text-xl">{title}</h3>
                <p className="text-slate-500 text-sm leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Recent Scans — only shown if the user has local history */}
      {history.length > 0 && (
        <section className="px-6 py-12 bg-white border-b border-slate-100">
          <div className="max-w-5xl mx-auto">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-bold text-slate-900">Recent Scans</h2>
                <p className="text-slate-500 text-sm mt-0.5">Stored locally in your browser</p>
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {history.slice(0, 6).map((entry) => {
                const scoreColor =
                  entry.score >= 70
                    ? 'text-green-700 bg-green-50 border-green-200'
                    : entry.score >= 40
                    ? 'text-amber-700 bg-amber-50 border-amber-200'
                    : 'text-red-700 bg-red-50 border-red-200';
                const ago = (() => {
                  const ms = Date.now() - new Date(entry.scannedAt).getTime();
                  const mins = Math.floor(ms / 60000);
                  if (mins < 60) return `${mins}m ago`;
                  const hrs = Math.floor(mins / 60);
                  if (hrs < 24) return `${hrs}h ago`;
                  return `${Math.floor(hrs / 24)}d ago`;
                })();
                return (
                  <div
                    key={entry.domain}
                    className="group relative flex items-center gap-4 p-4 border border-slate-200 rounded-xl hover:border-orange-300 hover:shadow-sm transition-all bg-white"
                  >
                    {/* Remove button */}
                    <button
                      onClick={(e) => { e.preventDefault(); handleRemove(entry.domain); }}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity text-slate-300 hover:text-slate-500 p-0.5"
                      title="Remove from history"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                      </svg>
                    </button>

                    {/* Score badge */}
                    <div className={`flex-shrink-0 w-12 h-12 rounded-xl border-2 flex items-center justify-center font-black text-xl ${scoreColor}`}>
                      {entry.score}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <a
                        href={`/scan?url=${encodeURIComponent(entry.url)}`}
                        className="block font-semibold text-slate-800 text-sm truncate hover:text-orange-600 transition-colors"
                      >
                        {entry.domain}
                      </a>
                      <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-400">
                        <span>{ago}</span>
                        {entry.critical > 0 && (
                          <span className="text-red-500 font-medium">· {entry.critical} critical</span>
                        )}
                        {entry.critical === 0 && entry.warnings > 0 && (
                          <span className="text-amber-500">· {entry.warnings} warnings</span>
                        )}
                        {entry.critical === 0 && entry.warnings === 0 && (
                          <span className="text-green-600">· Clean ✓</span>
                        )}
                      </div>
                    </div>

                    {/* Re-scan arrow */}
                    <a
                      href={`/scan?url=${encodeURIComponent(entry.url)}`}
                      className="flex-shrink-0 text-slate-300 group-hover:text-orange-400 transition-colors"
                      title="Re-scan"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="m9 18 6-6-6-6"/>
                      </svg>
                    </a>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* CTA */}
      <section className="bg-orange-50 border-y border-orange-100 px-6 py-20">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-3xl sm:text-4xl font-bold text-slate-900 mb-4">
            Ready to see what your app is exposing?
          </h2>
          <p className="text-slate-500 mb-3 text-lg">Takes under 30 seconds. No account. No installs.</p>
          <div className="flex items-center justify-center gap-6 mb-10 text-sm text-slate-500">
            <span className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5"><polyline points="20,6 9,17 4,12"/></svg>
              Under 30 seconds
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5"><polyline points="20,6 9,17 4,12"/></svg>
              No account needed
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5"><polyline points="20,6 9,17 4,12"/></svg>
              Free
            </span>
          </div>
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 max-w-lg mx-auto">
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="myapp.vercel.app"
              className="flex-1 w-full px-5 py-4 border-2 border-orange-200 rounded-xl focus:outline-none focus:border-orange-400 transition-colors text-slate-900 placeholder-slate-400 font-mono text-base min-h-[56px]"
              aria-label="Website URL to scan"
            />
            <button
              type="submit"
              className="w-full sm:w-auto px-7 py-4 bg-orange-500 hover:bg-orange-600 active:bg-orange-700 text-white font-bold rounded-xl transition-colors text-base min-h-[56px]"
            >
              Scan Now →
            </button>
          </form>
        </div>
      </section>

      {/* Footer */}
      <footer className="px-6 py-8 border-t border-slate-100">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-400">
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 bg-orange-500 rounded flex items-center justify-center">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <span>VibeScan by <a href="https://creativedigital.group" className="hover:text-slate-600 underline underline-offset-2" target="_blank" rel="noopener noreferrer">Creative Digital Group</a></span>
          </div>
          <div className="flex items-center gap-6">
            <span>Passive scans only — we never modify your app</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
