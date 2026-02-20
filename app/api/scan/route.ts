import { NextRequest, NextResponse } from 'next/server';

export const maxDuration = 30;

const SENSITIVE_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config',
  '/package.json',
  '/config.json',
  '/database.json',
  '/api/users',
  '/api/admin',
  '/api/config',
  '/admin',
  '/internal',
  '/debug',
  '/wp-admin',
  '/phpinfo.php',
];

const SECRET_PATTERNS: { name: string; pattern: RegExp; severity: 'critical' | 'warning' }[] = [
  { name: 'Supabase URL', pattern: /SUPABASE_URL|supabase\.co/g, severity: 'warning' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{40,}/g, severity: 'critical' },
  { name: 'Stripe Live Key', pattern: /pk_live_[a-zA-Z0-9]+|sk_live_[a-zA-Z0-9]+/g, severity: 'critical' },
  { name: 'Stripe Test Key', pattern: /pk_test_[a-zA-Z0-9]+|sk_test_[a-zA-Z0-9]+/g, severity: 'warning' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'critical' },
  { name: 'NEXT_PUBLIC Secret', pattern: /NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN)[A-Z_]*/g, severity: 'warning' },
  { name: 'Supabase JWT', pattern: /eyJhbGciOiJIUzI1NiJ[a-zA-Z0-9+/=._-]*/g, severity: 'critical' },
];

function normalizeUrl(url: string): string {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url.replace(/\/$/, '');
}

function getOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

async function discoverUrls(baseUrl: string): Promise<string[]> {
  const urls = new Set<string>();
  const origin = getOrigin(baseUrl);

  // 1. Sitemap
  try {
    const res = await fetchWithTimeout(`${baseUrl}/sitemap.xml`, {}, 5000);
    if (res.ok) {
      const text = await res.text();
      const matches = text.match(/<loc>([^<]+)<\/loc>/g) || [];
      matches.slice(0, 50).forEach(m => {
        const url = m.replace(/<\/?loc>/g, '').trim();
        urls.add(url);
      });
    }
  } catch {}

  // 2. Robots.txt
  try {
    const res = await fetchWithTimeout(`${baseUrl}/robots.txt`, {}, 5000);
    if (res.ok) {
      const text = await res.text();
      const lines = text.split('\n');
      lines.forEach(line => {
        const match = line.match(/^(?:Disallow|Allow):\s*(.+)/i);
        if (match && match[1].trim() !== '/') {
          const path = match[1].trim();
          if (path && !path.includes('*')) {
            urls.add(`${origin}${path}`);
          }
        }
      });
    }
  } catch {}

  // 3. Homepage links
  try {
    const res = await fetchWithTimeout(baseUrl, {}, 5000);
    if (res.ok) {
      const text = await res.text();
      const hrefMatches = text.match(/href=["']([^"']+)["']/g) || [];
      hrefMatches.forEach(m => {
        const href = m.replace(/href=["']/, '').replace(/["']$/, '');
        if (href.startsWith('/') && !href.startsWith('//')) {
          urls.add(`${origin}${href}`);
        } else if (href.startsWith(origin)) {
          urls.add(href);
        }
      });
    }
  } catch {}

  return Array.from(urls).sort().slice(0, 50);
}

async function checkSensitivePaths(baseUrl: string): Promise<{ path: string; status: number }[]> {
  const exposed: { path: string; status: number }[] = [];
  const origin = getOrigin(baseUrl);

  const checks = SENSITIVE_PATHS.map(async (path) => {
    try {
      const res = await fetchWithTimeout(`${origin}${path}`, { method: 'HEAD' }, 5000);
      if (res.status === 200) {
        exposed.push({ path, status: res.status });
      }
    } catch {}
  });

  await Promise.allSettled(checks);
  return exposed;
}

async function checkSecurityHeaders(baseUrl: string): Promise<Record<string, string | null>> {
  const headers: Record<string, string | null> = {
    'strict-transport-security': null,
    'content-security-policy': null,
    'x-frame-options': null,
    'x-content-type-options': null,
    'referrer-policy': null,
    'permissions-policy': null,
  };

  try {
    const res = await fetchWithTimeout(baseUrl, {}, 8000);
    for (const key of Object.keys(headers)) {
      headers[key] = res.headers.get(key);
    }
  } catch {}

  return headers;
}

async function detectApiKeys(baseUrl: string): Promise<{ type: string; preview: string; severity: 'critical' | 'warning' }[]> {
  const findings: { type: string; preview: string; severity: 'critical' | 'warning' }[] = [];
  const origin = getOrigin(baseUrl);

  try {
    const res = await fetchWithTimeout(baseUrl, {}, 8000);
    if (!res.ok) return findings;
    const html = await res.text();

    // Extract same-domain script tags
    const scriptMatches = html.match(/<script[^>]+src=["']([^"']+)["']/g) || [];
    const scriptUrls: string[] = [];

    for (const match of scriptMatches) {
      const src = match.match(/src=["']([^"']+)["']/)?.[1];
      if (!src) continue;
      // Skip CDN/external scripts
      if (src.startsWith('http') && !src.startsWith(origin)) continue;
      if (src.includes('cdn.') || src.includes('googleapis') || src.includes('node_modules')) continue;

      const fullUrl = src.startsWith('/') ? `${origin}${src}` : src;
      scriptUrls.push(fullUrl);
    }

    // Fetch up to 3 JS bundles
    const toCheck = scriptUrls.slice(0, 3);
    for (const scriptUrl of toCheck) {
      try {
        const jsRes = await fetchWithTimeout(scriptUrl, {}, 6000);
        if (!jsRes.ok) continue;
        const jsContent = await jsRes.text();

        for (const { name, pattern, severity } of SECRET_PATTERNS) {
          pattern.lastIndex = 0;
          const match = jsContent.match(pattern);
          if (match) {
            findings.push({
              type: name,
              preview: match[0].substring(0, 8) + '...',
              severity,
            });
          }
        }
      } catch {}
    }
  } catch {}

  return findings;
}

async function checkCors(baseUrl: string): Promise<{ open: boolean; header: string | null }> {
  const origin = getOrigin(baseUrl);
  const endpoints = [`${origin}/api/`, `${origin}/api/health`];

  for (const endpoint of endpoints) {
    try {
      const res = await fetchWithTimeout(endpoint, {
        method: 'OPTIONS',
        headers: { Origin: 'https://evil-attacker.com' },
      }, 5000);
      const header = res.headers.get('access-control-allow-origin');
      if (header === '*') {
        return { open: true, header };
      }
    } catch {}
  }

  return { open: false, header: null };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const rawUrl = body.url as string;

    if (!rawUrl) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    const baseUrl = normalizeUrl(rawUrl);

    // Validate URL
    try {
      new URL(baseUrl);
    } catch {
      return NextResponse.json({ error: 'Invalid URL' }, { status: 400 });
    }

    const TIMEOUT = 15000;

    // Run all checks with overall timeout
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Scan timeout')), TIMEOUT)
    );

    const scanPromise = runScan(baseUrl);
    
    try {
      const result = await Promise.race([scanPromise, timeoutPromise]);
      return NextResponse.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Scan failed';
      return NextResponse.json({ error: message }, { status: 500 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }
}

async function runScan(baseUrl: string) {
  const checks: {
    id: string;
    category: 'pages' | 'headers' | 'secrets' | 'exposure' | 'ssl';
    name: string;
    status: 'critical' | 'warning' | 'pass' | 'info';
    detail: string;
    value?: string;
  }[] = [];

  // Check 6: SSL (immediate)
  const isHttps = baseUrl.startsWith('https://');
  checks.push({
    id: 'ssl',
    category: 'ssl',
    name: 'HTTPS / SSL',
    status: isHttps ? 'pass' : 'critical',
    detail: isHttps ? 'Site uses HTTPS — traffic is encrypted.' : 'Site does not use HTTPS. All traffic is unencrypted.',
  });

  // Run remaining checks in parallel
  const [discoveredUrls, sensitivePaths, securityHeaders, apiKeys, cors] = await Promise.allSettled([
    discoverUrls(baseUrl),
    checkSensitivePaths(baseUrl),
    checkSecurityHeaders(baseUrl),
    detectApiKeys(baseUrl),
    checkCors(baseUrl),
  ]);

  // URL discovery results
  const urls = discoveredUrls.status === 'fulfilled' ? discoveredUrls.value : [];
  checks.push({
    id: 'url-discovery',
    category: 'pages',
    name: 'Page Discovery',
    status: 'info',
    detail: `Found ${urls.length} URLs via sitemap, robots.txt, and link crawling.`,
    value: `${urls.length} URLs discovered`,
  });

  // Sensitive paths
  const exposed = sensitivePaths.status === 'fulfilled' ? sensitivePaths.value : [];
  if (exposed.length === 0) {
    checks.push({
      id: 'sensitive-paths',
      category: 'exposure',
      name: 'Sensitive Path Exposure',
      status: 'pass',
      detail: 'No sensitive files or paths found publicly accessible.',
    });
  } else {
    for (const { path } of exposed) {
      const isWordPress = path === '/wp-admin';
      const isCritical = ['/.env', '/.env.local', '/.env.production', '/.git/config', '/database.json'].includes(path);
      checks.push({
        id: `exposure-${path.replace(/\//g, '-')}`,
        category: 'exposure',
        name: isWordPress ? 'WordPress Detected' : `Exposed: ${path}`,
        status: isCritical ? 'critical' : 'warning',
        detail: isCritical
          ? `⚠️ ${path} is publicly accessible! This file may contain secrets, API keys, or database credentials.`
          : `${path} returned HTTP 200. Review whether this should be publicly accessible.`,
        value: path,
      });
    }
  }

  // Security headers
  const headers = securityHeaders.status === 'fulfilled' ? securityHeaders.value : {};
  const headerLabels: Record<string, string> = {
    'strict-transport-security': 'HSTS (Strict-Transport-Security)',
    'content-security-policy': 'Content-Security-Policy',
    'x-frame-options': 'X-Frame-Options',
    'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
  };
  const headerDescriptions: Record<string, { pass: string; fail: string }> = {
    'strict-transport-security': {
      pass: 'HSTS is set — browsers will always use HTTPS.',
      fail: 'HSTS missing — browsers may downgrade to HTTP.',
    },
    'content-security-policy': {
      pass: 'CSP header present — helps prevent XSS attacks.',
      fail: 'No CSP header — site is more vulnerable to XSS.',
    },
    'x-frame-options': {
      pass: 'X-Frame-Options set — protects against clickjacking.',
      fail: 'X-Frame-Options missing — site can be embedded in iframes (clickjacking risk).',
    },
    'x-content-type-options': {
      pass: 'X-Content-Type-Options set — prevents MIME sniffing.',
      fail: 'X-Content-Type-Options missing — browsers may sniff content types.',
    },
    'referrer-policy': {
      pass: 'Referrer-Policy set — controls referrer information.',
      fail: 'Referrer-Policy missing — full URLs may leak in referrer headers.',
    },
    'permissions-policy': {
      pass: 'Permissions-Policy set — controls browser features.',
      fail: 'Permissions-Policy missing — browser features not explicitly restricted.',
    },
  };

  for (const [key, label] of Object.entries(headerLabels)) {
    const value = headers[key];
    const desc = headerDescriptions[key];
    checks.push({
      id: `header-${key}`,
      category: 'headers',
      name: label,
      status: value ? 'pass' : 'warning',
      detail: value ? desc.pass : desc.fail,
      value: value || undefined,
    });
  }

  // API key detection
  const keys = apiKeys.status === 'fulfilled' ? apiKeys.value : [];
  if (keys.length === 0) {
    checks.push({
      id: 'api-keys',
      category: 'secrets',
      name: 'API Key Exposure in JS',
      status: 'pass',
      detail: 'No API keys or secrets detected in public JavaScript bundles.',
    });
  } else {
    for (const key of keys) {
      checks.push({
        id: `secret-${key.type.toLowerCase().replace(/\s/g, '-')}`,
        category: 'secrets',
        name: `Exposed: ${key.type}`,
        status: key.severity,
        detail: `A ${key.type} was found in public JavaScript. Rotate this key immediately.`,
        value: key.preview,
      });
    }
  }

  // CORS
  const corsResult = cors.status === 'fulfilled' ? cors.value : { open: false, header: null };
  checks.push({
    id: 'cors',
    category: 'headers',
    name: 'CORS Policy',
    status: corsResult.open ? 'warning' : 'pass',
    detail: corsResult.open
      ? 'CORS is wide open (Access-Control-Allow-Origin: *). Any website can make API requests to your app.'
      : 'CORS policy appears correctly configured.',
    value: corsResult.header || undefined,
  });

  // Calculate score
  const criticalCount = checks.filter(c => c.status === 'critical').length;
  const warningCount = checks.filter(c => c.status === 'warning').length;
  const passCount = checks.filter(c => c.status === 'pass').length;

  let score = 100;
  score -= criticalCount * 20;
  score -= warningCount * 5;
  score = Math.max(0, Math.min(100, score));

  // Sort: critical first, then warning, then pass, then info
  const statusOrder = { critical: 0, warning: 1, pass: 2, info: 3 };
  checks.sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

  return {
    url: baseUrl,
    scannedAt: new Date().toISOString(),
    score,
    summary: {
      critical: criticalCount,
      warnings: warningCount,
      passed: passCount,
    },
    discoveredUrls: urls,
    checks,
  };
}
