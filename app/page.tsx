'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const router = useRouter();

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
      setError('That doesn\'t look like a valid URL. Try something like: myapp.vercel.app');
      return;
    }

    const encoded = encodeURIComponent(normalized);
    router.push(`/scan?url=${encoded}`);
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
      <section className="px-6 pt-20 pb-16 text-center">
        <div className="max-w-3xl mx-auto">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 bg-orange-50 border border-orange-200 rounded-full px-4 py-1.5 mb-8">
            <span className="text-orange-600 text-sm font-medium">Built with Lovable, Bolt, Cursor, or V0? You need this.</span>
          </div>

          <h1 className="text-5xl sm:text-6xl font-bold text-slate-900 leading-tight mb-6">
            Is your app
            <span className="text-orange-500"> leaking?</span>
          </h1>

          <p className="text-xl text-slate-500 leading-relaxed mb-12 max-w-2xl mx-auto">
            AI tools make building fast — but they often leave security gaps that can expose your users&apos; data,
            your API keys, or your entire source code. VibeScan finds what you missed, in plain English.
          </p>

          {/* Scan form */}
          <form onSubmit={handleSubmit} className="max-w-xl mx-auto">
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="myapp.vercel.app"
                className="flex-1 px-5 py-4 text-lg border-2 border-slate-200 rounded-xl focus:outline-none focus:border-orange-400 transition-colors text-slate-900 placeholder-slate-400 font-mono"
                aria-label="Website URL to scan"
              />
              <button
                type="submit"
                className="px-8 py-4 bg-orange-500 hover:bg-orange-600 text-white font-semibold text-lg rounded-xl transition-colors shadow-sm whitespace-nowrap"
              >
                Scan Now →
              </button>
            </div>
            {error && (
              <p className="mt-3 text-red-500 text-sm text-left">{error}</p>
            )}
            <p className="mt-3 text-sm text-slate-400">
              Free · No signup required · Passive scan only (we never modify your app)
            </p>
          </form>
        </div>
      </section>

      {/* Social proof strip */}
      <section className="bg-slate-50 border-y border-slate-100 py-10 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <p className="text-slate-500 text-sm font-medium uppercase tracking-wide mb-8">What VibeScan checks for</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-8">
            <div className="flex flex-col items-center gap-3">
              <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2">
                  <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                </svg>
              </div>
              <h3 className="font-semibold text-slate-900">Pages discovered</h3>
              <p className="text-slate-500 text-sm text-center leading-relaxed">
                We map your sitemap, robots.txt, and links to show every page visible to the internet — including ones you might have forgotten about.
              </p>
            </div>
            <div className="flex flex-col items-center gap-3">
              <div className="w-12 h-12 bg-orange-100 rounded-xl flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <h3 className="font-semibold text-slate-900">Security headers</h3>
              <p className="text-slate-500 text-sm text-center leading-relaxed">
                Six protective settings that most AI-generated apps are missing. We explain each one in plain English and give you the exact fix.
              </p>
            </div>
            <div className="flex flex-col items-center gap-3">
              <div className="w-12 h-12 bg-red-100 rounded-xl flex items-center justify-center">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                  <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
              </div>
              <h3 className="font-semibold text-slate-900">Exposed secrets</h3>
              <p className="text-slate-500 text-sm text-center leading-relaxed">
                API keys accidentally bundled into your JavaScript, .env files left public, and Git repos that shouldn&apos;t be accessible.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="px-6 py-20">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-bold text-slate-900 mb-3">How it works</h2>
            <p className="text-slate-500 text-lg">Three steps. About 15 seconds. No account needed.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-10">
            {[
              { step: '1', title: 'Enter your URL', desc: "Paste your app's URL — the same one your users visit. No login, no sign-up, no credit card." },
              { step: '2', title: 'We run the checks', desc: 'We make standard HTTP requests to your app — the same requests any browser would make. We never modify, inject, or stress-test your app.' },
              { step: '3', title: 'Read your report', desc: 'Every finding is explained in plain English with a severity rating and a ready-to-use fix prompt for Lovable, Cursor, or ChatGPT.' },
            ].map(({ step, title, desc }) => (
              <div key={step} className="flex flex-col gap-3">
                <div className="w-10 h-10 bg-orange-500 rounded-full flex items-center justify-center text-white font-bold text-lg flex-shrink-0">
                  {step}
                </div>
                <h3 className="font-semibold text-slate-900 text-lg">{title}</h3>
                <p className="text-slate-500 text-sm leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="bg-orange-50 border-y border-orange-100 px-6 py-16">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-slate-900 mb-4">
            Ready to see what your app is exposing?
          </h2>
          <p className="text-slate-500 mb-8 text-lg">Takes 15 seconds. No account. No installs.</p>
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 max-w-lg mx-auto">
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="myapp.vercel.app"
              className="flex-1 px-5 py-4 border-2 border-orange-200 rounded-xl focus:outline-none focus:border-orange-400 transition-colors text-slate-900 placeholder-slate-400 font-mono text-base"
            />
            <button
              type="submit"
              className="px-6 py-4 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors"
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
