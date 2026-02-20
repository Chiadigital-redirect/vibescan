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

const SECRET_PATTERNS: { name: string; pattern: RegExp; severity: 'critical' | 'warning'; isServiceRole?: boolean }[] = [
  { name: 'Supabase URL', pattern: /SUPABASE_URL|supabase\.co/g, severity: 'warning' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{40,}/g, severity: 'critical' },
  { name: 'Stripe Live Key', pattern: /pk_live_[a-zA-Z0-9]+|sk_live_[a-zA-Z0-9]+/g, severity: 'critical' },
  { name: 'Stripe Test Key', pattern: /pk_test_[a-zA-Z0-9]+|sk_test_[a-zA-Z0-9]+/g, severity: 'warning' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'critical' },
  { name: 'NEXT_PUBLIC Secret', pattern: /NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN)[A-Z_]*/g, severity: 'warning' },
  { name: 'Supabase JWT', pattern: /eyJ[a-zA-Z0-9+/=._-]{100,}/g, severity: 'critical' },
];

// Supabase URL pattern for extraction
const SUPABASE_URL_PATTERN = /https:\/\/[a-z0-9-]+\.supabase\.co/g;

export interface ExposedTable {
  name: string;
  columns: string[];
  sampleRows: Record<string, unknown>[];
  totalRows?: number;
  rls: boolean; // whether RLS appears to be blocking data
}

export interface DataLeaks {
  supabaseUrl: string;
  keyPreview: string;
  tables: ExposedTable[];
  blockedTables: string[];
  tablesFound: number;
  openTables: number;
}

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

  // 3. Homepage — extract links AND JS bundle URLs
  const jsBundleUrls: string[] = [];
  try {
    const res = await fetchWithTimeout(baseUrl, {}, 5000);
    if (res.ok) {
      const text = await res.text();

      // Anchor links
      const hrefMatches = text.match(/href=["']([^"']+)["']/g) || [];
      hrefMatches.forEach(m => {
        const href = m.replace(/href=["']/, '').replace(/["']$/, '');
        if (href.startsWith('/') && !href.startsWith('//') && !href.endsWith('.css') && !href.endsWith('.ico')) {
          urls.add(`${origin}${href}`);
        } else if (href.startsWith(origin)) {
          urls.add(href);
        }
      });

      // Collect JS bundle src paths for route extraction
      const scriptMatches = text.match(/src=["']([^"']+\.js[^"']*)["']/g) || [];
      for (const m of scriptMatches) {
        const src = m.replace(/src=["']/, '').replace(/["']$/, '');
        if (src.includes('cdn.') || src.includes('googleapis') || src.includes('analytics')) continue;
        const fullUrl = src.startsWith('/') ? `${origin}${src}` : src.startsWith('http') ? src : `${origin}/${src}`;
        jsBundleUrls.push(fullUrl);
      }
    }
  } catch {}

  // 4. JS bundle route extraction — finds routes in SPAs (React Router, Next.js, Vue Router, etc.)
  //    Looks for quoted path strings like "/about", "/dashboard/settings" etc.
  const routePathPattern = /"(\/[a-z][a-z0-9]*(?:\/[a-z][a-z0-9-]*){0,4})"/g;
  const skippedPrefixes = ['/api/', '/assets/', '/static/', '/_next/', '/fonts/', '/images/', '/_vercel'];

  for (const bundleUrl of jsBundleUrls.slice(0, 4)) {
    try {
      const jsRes = await fetchWithTimeout(bundleUrl, {}, 6000);
      if (!jsRes.ok) continue;
      const js = await jsRes.text();
      // Skip very small files (likely not the main bundle) or files with no routes
      if (js.length < 5000) continue;

      let match: RegExpExecArray | null;
      routePathPattern.lastIndex = 0;
      while ((match = routePathPattern.exec(js)) !== null) {
        const path = match[1];
        // Filter out false positives (CSS classes, short strings, asset paths)
        if (path.length < 2) continue;
        if (skippedPrefixes.some(p => path.startsWith(p))) continue;
        if (path.includes('.') && !path.endsWith('/')) continue; // skip filenames like /foo.bar
        urls.add(`${origin}${path}`);
      }
    } catch {}
  }

  // Deduplicate and return — sort warnings/interesting paths first
  const result = Array.from(urls)
    .filter(u => {
      try { return new URL(u).hostname === new URL(origin).hostname; } catch { return false; }
    })
    .sort()
    .slice(0, 60);

  return result;
}

// Content validators — confirm the response is actually the sensitive file, not an SPA catch-all
const PATH_VALIDATORS: Record<string, (body: string, contentType: string) => boolean> = {
  '/.git/config': (b) => b.includes('[core]') || b.includes('[remote') || b.includes('[branch'),
  '/.env': (b, ct) => !ct.includes('text/html') && /^[A-Z_]+=.+/m.test(b),
  '/.env.local': (b, ct) => !ct.includes('text/html') && /^[A-Z_]+=.+/m.test(b),
  '/.env.production': (b, ct) => !ct.includes('text/html') && /^[A-Z_]+=.+/m.test(b),
  '/package.json': (b) => { try { const j = JSON.parse(b); return !!j.name && !!j.dependencies; } catch { return false; } },
  '/database.json': (b) => { try { JSON.parse(b); return b.length > 10; } catch { return false; } },
  '/config.json': (b) => { try { JSON.parse(b); return b.length > 10; } catch { return false; } },
  '/api/users': (b) => { try { const j = JSON.parse(b); return Array.isArray(j) || (typeof j === 'object' && (j.users || j.data || j.email)); } catch { return false; } },
  '/api/admin': (b, ct) => !ct.includes('text/html'),
  '/api/config': (b, ct) => !ct.includes('text/html'),
  '/phpinfo.php': (b) => b.includes('PHP Version') || b.includes('phpinfo'),
  '/wp-admin': (b) => b.includes('wp-login') || b.includes('WordPress') || b.includes('wp-admin'),
};

// Generic SPA catch-all detector — returns true if body looks like an SPA fallback
function isSpaFallback(body: string, contentType: string): boolean {
  if (!contentType.includes('text/html')) return false;
  // Common SPA indicators in the HTML
  return (
    body.includes('id="root"') ||
    body.includes('id="app"') ||
    body.includes('__NEXT_DATA__') ||
    body.includes('_next/static') ||
    (body.includes('<script') && body.includes('bundle') && body.length < 10000)
  );
}

async function checkSensitivePaths(baseUrl: string): Promise<{ path: string; status: number; preview?: string }[]> {
  const exposed: { path: string; status: number; preview?: string }[] = [];
  const origin = getOrigin(baseUrl);

  const checks = SENSITIVE_PATHS.map(async (path) => {
    try {
      // Use GET so we can inspect the body — HEAD alone is not reliable for SPAs
      const res = await fetchWithTimeout(`${origin}${path}`, { method: 'GET' }, 5000);
      if (res.status !== 200) return;

      const contentType = res.headers.get('content-type') || '';
      const body = await res.text();

      // Reject SPA catch-all responses
      if (isSpaFallback(body, contentType)) return;

      // Run path-specific validator if we have one
      const validator = PATH_VALIDATORS[path];
      if (validator && !validator(body, contentType)) return;

      // If no specific validator, use generic non-HTML check for API/data paths
      if (!validator && contentType.includes('text/html')) return;

      // Extract a safe preview snippet (no secrets, just enough to confirm it's real)
      let preview: string | undefined;
      if (path.includes('.env')) {
        // Show key names only, not values
        const keyNames = (body.match(/^([A-Z_]+)=/gm) || []).slice(0, 5).join(', ');
        if (keyNames) preview = `Contains: ${keyNames}...`;
      } else if (path === '/package.json') {
        try {
          const pkg = JSON.parse(body);
          preview = `${pkg.name}@${pkg.version} — ${Object.keys(pkg.dependencies || {}).length} dependencies`;
        } catch {}
      } else if (path.includes('.git')) {
        const firstLine = body.split('\n').find(l => l.trim()) || '';
        preview = firstLine.trim();
      }

      exposed.push({ path, status: res.status, preview });
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

interface ApiKeyFinding {
  type: string;
  preview: string;
  severity: 'critical' | 'warning';
  supabaseUrl?: string;
  supabaseKey?: string;
}

async function detectApiKeys(baseUrl: string): Promise<ApiKeyFinding[]> {
  const findings: ApiKeyFinding[] = [];
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

        // Extract Supabase URL for data exposure check
        let detectedSupabaseUrl: string | undefined;
        let detectedSupabaseKey: string | undefined;
        const urlMatches = jsContent.match(SUPABASE_URL_PATTERN);
        if (urlMatches && urlMatches.length > 0) {
          detectedSupabaseUrl = urlMatches[0];
        }

        for (const { name, pattern, severity } of SECRET_PATTERNS) {
          pattern.lastIndex = 0;
          const match = jsContent.match(pattern);
          if (match) {
            const finding: ApiKeyFinding = {
              type: name,
              preview: match[0].substring(0, 8) + '...',
              severity,
            };

            // If this is a Supabase JWT, decode it to check if it's anon or service_role
            if (name === 'Supabase JWT' && detectedSupabaseUrl) {
              pattern.lastIndex = 0;
              const fullMatches = jsContent.match(pattern) || [];
              for (const fullKey of fullMatches) {
                try {
                  const parts = fullKey.split('.');
                  if (parts.length >= 2) {
                    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
                    if (payload.role === 'service_role') {
                      // SERVICE ROLE KEY — this bypasses ALL RLS, much worse
                      findings.push({
                        type: 'Supabase Service Role Key',
                        preview: fullKey.substring(0, 8) + '...',
                        severity: 'critical',
                        supabaseUrl: detectedSupabaseUrl,
                        supabaseKey: fullKey,
                      });
                    } else if (payload.role === 'anon' || payload.iss === 'supabase') {
                      // Anon key — respects RLS but still dangerous if tables aren't protected
                      finding.supabaseUrl = detectedSupabaseUrl;
                      finding.supabaseKey = fullKey;
                      detectedSupabaseKey = fullKey;
                    }
                  }
                } catch {
                  // Fallback: treat first match as anon key
                  if (!detectedSupabaseKey) {
                    finding.supabaseUrl = detectedSupabaseUrl;
                    finding.supabaseKey = fullKey;
                    detectedSupabaseKey = fullKey;
                  }
                }
              }
            }

            findings.push(finding);
          }
        }

        // If we found a supabase URL but no JWT yet, look for the anon key pattern more broadly
        if (detectedSupabaseUrl && !detectedSupabaseKey) {
          // Look for any JWT-like string near the supabase URL
          const anonKeyPattern = /eyJ[a-zA-Z0-9+/=._-]{100,}/g;
          const anonMatches = jsContent.match(anonKeyPattern);
          if (anonMatches) {
            for (const key of anonMatches) {
              // Filter to likely anon keys (they contain "anon" or "role" when base64 decoded)
              try {
                const parts = key.split('.');
                if (parts.length >= 2) {
                  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
                  if (payload.role === 'anon' || payload.iss === 'supabase') {
                    // Already added as Supabase JWT finding, just enrich it
                    const existing = findings.find(f => f.type === 'Supabase JWT');
                    if (existing) {
                      existing.supabaseUrl = detectedSupabaseUrl;
                      existing.supabaseKey = key;
                    }
                    break;
                  }
                }
              } catch {}
            }
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

// --- Supabase Data Exposure Check ---

async function checkSupabaseDataExposure(supabaseUrl: string, anonKey: string): Promise<DataLeaks | null> {
  const cleanUrl = supabaseUrl.replace(/\/$/, '');

  // 1. Fetch OpenAPI spec to discover ALL table names + column schemas
  let tableNames: string[] = [];
  const columnSchemas: Record<string, string[]> = {};

  try {
    const specRes = await fetchWithTimeout(`${cleanUrl}/rest/v1/`, {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        Accept: 'application/json',
      },
    }, 8000);

    if (specRes.ok) {
      const spec = await specRes.json() as {
        definitions?: Record<string, { properties?: Record<string, unknown> }>;
      };
      if (spec.definitions) {
        tableNames = Object.keys(spec.definitions).filter(name =>
          !name.startsWith('_') && !name.includes('pg_') && !name.includes('information_schema')
        ).slice(0, 12);

        // Extract column names from the schema definitions
        for (const tableName of tableNames) {
          const def = spec.definitions[tableName];
          if (def?.properties) {
            columnSchemas[tableName] = Object.keys(def.properties);
          }
        }
      }
    }
  } catch {}

  if (tableNames.length === 0) return null;

  // 2. For each table, try to fetch sample rows AND get exact count
  const tables: ExposedTable[] = [];
  const blockedTables: string[] = [];

  const tableChecks = tableNames.map(async (tableName) => {
    try {
      const res = await fetchWithTimeout(
        `${cleanUrl}/rest/v1/${encodeURIComponent(tableName)}?limit=3`,
        {
          headers: {
            apikey: anonKey,
            Authorization: `Bearer ${anonKey}`,
            Accept: 'application/json',
            Prefer: 'count=exact',
          },
        },
        6000
      );

      if (!res.ok) {
        blockedTables.push(tableName);
        return;
      }

      const rows = await res.json() as Record<string, unknown>[];
      const countHeader = res.headers.get('content-range');
      let totalRows: number | undefined;
      if (countHeader) {
        const match = countHeader.match(/\/(\d+)$/);
        if (match) totalRows = parseInt(match[1]);
      }

      if (Array.isArray(rows) && rows.length > 0) {
        tables.push({
          name: tableName,
          columns: Object.keys(rows[0]),
          sampleRows: rows,
          totalRows,
          rls: false,
        });
      } else if (Array.isArray(rows)) {
        // Empty or RLS returning empty — still accessible, show schema from spec
        const cols = columnSchemas[tableName] || [];
        tables.push({
          name: tableName,
          columns: cols,
          sampleRows: [],
          totalRows: totalRows ?? 0,
          rls: false,
        });
      }
    } catch {
      blockedTables.push(tableName);
    }
  });

  await Promise.allSettled(tableChecks);

  const openTables = tables.filter(t => t.sampleRows.length > 0).length;

  return {
    supabaseUrl: cleanUrl,
    keyPreview: anonKey.substring(0, 20) + '...',
    tables,           // ALL accessible tables (with and without data)
    blockedTables,    // Tables where RLS blocked access
    tablesFound: tableNames.length,
    openTables,
  };
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

    const TIMEOUT = 25000;

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
    for (const { path, preview } of exposed) {
      const isWordPress = path === '/wp-admin';
      const isCritical = ['/.env', '/.env.local', '/.env.production', '/.git/config', '/database.json'].includes(path);
      checks.push({
        id: `exposure-${path.replace(/\//g, '-')}`,
        category: 'exposure',
        name: isWordPress ? 'WordPress Detected' : `Exposed: ${path}`,
        status: isCritical ? 'critical' : 'warning',
        detail: isCritical
          ? `⚠️ ${path} is publicly accessible! This file may contain secrets, API keys, or database credentials.${preview ? ` Preview: ${preview}` : ''}`
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

  // API key detection + Supabase data exposure
  const keys = apiKeys.status === 'fulfilled' ? apiKeys.value : [];
  let dataLeaks: DataLeaks | null = null;

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
      const isServiceRole = key.type === 'Supabase Service Role Key';
      checks.push({
        id: `secret-${key.type.toLowerCase().replace(/\s/g, '-')}`,
        category: 'secrets',
        name: isServiceRole ? '🚨 Supabase Service Role Key Exposed' : `Exposed: ${key.type}`,
        status: key.severity,
        detail: isServiceRole
          ? `CRITICAL: Your Supabase service_role key is in public JavaScript. This key bypasses ALL Row Level Security — every table, every row, no restrictions. Anyone who has this key owns your entire database.`
          : `A ${key.type} was found in public JavaScript. Rotate this key immediately.`,
        value: key.preview,
      });
    }

    // If we found Supabase credentials, check for live data exposure
    const supabaseFinding = keys.find(k => k.supabaseUrl && k.supabaseKey);
    if (supabaseFinding?.supabaseUrl && supabaseFinding?.supabaseKey) {
      try {
        dataLeaks = await checkSupabaseDataExposure(supabaseFinding.supabaseUrl, supabaseFinding.supabaseKey);

        if (dataLeaks && (dataLeaks.openTables > 0 || dataLeaks.tables.length > 0)) {
          const accessibleCount = dataLeaks.tables.length;
          checks.push({
            id: 'supabase-data-exposure',
            category: 'secrets',
            name: 'Database Accessible via Exposed Token',
            status: 'critical',
            detail: `${accessibleCount} ${accessibleCount === 1 ? 'table' : 'tables'} accessible with your public anon key. ${dataLeaks.openTables > 0 ? `${dataLeaks.openTables} returning live rows.` : ''} ${dataLeaks.blockedTables?.length > 0 ? `${dataLeaks.blockedTables.length} protected by RLS.` : ''}`,
            value: `${accessibleCount} accessible tables`,
          });
        }
      } catch {}
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
    dataLeaks,
  };
}
