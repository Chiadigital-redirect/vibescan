// Human-readable copy and fix prompts for each check type

export interface CheckCopy {
  headline: string;          // Big, plain-English headline
  plainEnglish: string;      // "5-year-old" explanation paragraph
  fixPrompt?: string;        // Ready-to-paste AI prompt for the fix
  fixPromptWarning?: string; // Warning shown before the fix prompt
}

type SeverityLabel = {
  label: string;
  emoji: string;
  description: string;
  color: string;
  bg: string;
  border: string;
};

export const severityLabels: Record<string, SeverityLabel> = {
  critical: {
    label: 'Urgent — fix this today',
    emoji: '🔴',
    description: 'This is a serious security risk that needs immediate attention.',
    color: 'text-red-700',
    bg: 'bg-red-50',
    border: 'border-red-200',
  },
  warning: {
    label: 'Worth fixing soon',
    emoji: '🟡',
    description: 'Not immediately dangerous, but could become a problem.',
    color: 'text-amber-700',
    bg: 'bg-amber-50',
    border: 'border-amber-200',
  },
  pass: {
    label: "You're good here",
    emoji: '🟢',
    description: 'This check passed. Nice work!',
    color: 'text-green-700',
    bg: 'bg-green-50',
    border: 'border-green-200',
  },
  info: {
    label: 'For your information',
    emoji: '🔵',
    description: 'Just something to be aware of.',
    color: 'text-blue-700',
    bg: 'bg-blue-50',
    border: 'border-blue-200',
  },
};

// URL path classifications for discovered URLs
export function classifyUrl(url: string): { emoji: string; label: string; severity: 'critical' | 'warning' | 'info' } {
  const path = (() => {
    try { return new URL(url).pathname.toLowerCase(); }
    catch { return url.toLowerCase(); }
  })();

  if (path.includes('/admin') || path.includes('/administrator')) {
    return { emoji: '⚠️', label: 'Admin page — is this supposed to be public?', severity: 'warning' };
  }
  if (path.match(/\/api\/users?($|\/)/)) {
    return { emoji: '🔴', label: 'Lists your users — can anyone access this?', severity: 'critical' };
  }
  if (path.match(/\/api\//)) {
    return { emoji: '🔵', label: 'API endpoint — make sure it requires login', severity: 'info' };
  }
  if (path.includes('/internal') || path.includes('/private')) {
    return { emoji: '⚠️', label: 'Internal page — should this be visible to the public?', severity: 'warning' };
  }
  if (path.includes('/debug') || path.includes('/test')) {
    return { emoji: '⚠️', label: 'Debug/test page — should not be on a live site', severity: 'warning' };
  }
  if (path.includes('/dashboard')) {
    return { emoji: '🔵', label: 'Dashboard — check that login is required', severity: 'info' };
  }
  if (path.includes('/settings')) {
    return { emoji: '🔵', label: 'Settings page — make sure only logged-in users can see this', severity: 'info' };
  }
  if (path === '/' || path === '') {
    return { emoji: '🌐', label: 'Homepage', severity: 'info' };
  }
  return { emoji: '📄', label: 'Page', severity: 'info' };
}

export const checkCopy: Record<string, CheckCopy> = {
  // SSL
  'ssl-pass': {
    headline: 'Your site uses a secure connection',
    plainEnglish: 'When people visit your site, their data is encrypted in transit — like sending a letter in a locked box instead of a postcard. This is the minimum standard for any website today.',
  },
  'ssl-critical': {
    headline: "Your site doesn't use HTTPS",
    plainEnglish: "Everything your users send to your site — passwords, credit card numbers, personal details — travels across the internet in plain text. Anyone on the same WiFi network could read it. This is like shouting passwords across a coffee shop.",
    fixPrompt: `My website is currently running on HTTP instead of HTTPS. Help me enable HTTPS/SSL. I'm using [your hosting platform — e.g. Vercel, Netlify, Railway]. Give me the exact steps to enable SSL. Only tell me what to change on my hosting platform — do not modify any application code.`,
    fixPromptWarning: 'After enabling HTTPS, test that all pages load correctly and that HTTP links redirect to HTTPS.',
  },

  // Security Headers
  'header-strict-transport-security-pass': {
    headline: 'Browsers are forced to always use your secure connection',
    plainEnglish: 'Once someone visits your site, their browser remembers to always use the secure version. Even if someone tries to trick them into visiting the insecure version, it won\'t work.',
  },
  'header-strict-transport-security-warning': {
    headline: 'Browsers might accidentally use an insecure connection',
    plainEnglish: "Even if your site has HTTPS, browsers might still try the insecure (HTTP) version first if someone types your URL without 'https://'. This header tells them to always use the secure version, no exceptions.",
    fixPrompt: `Add the Strict-Transport-Security (HSTS) security header to my Next.js app. Add it to the headers() section in next.config.js only. The value should be "max-age=31536000; includeSubDomains". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: 'Only enable HSTS after confirming your SSL certificate works correctly. Once set, browsers will refuse to load your site over HTTP for up to a year.',
  },
  'header-content-security-policy-pass': {
    headline: "Your app blocks attempts to inject fake content",
    plainEnglish: "You have a rulebook that tells the browser exactly where content on your page is allowed to come from. Attackers can't sneak in fake buttons, fake forms, or malicious scripts.",
  },
  'header-content-security-policy-warning': {
    headline: 'Someone could inject fake content into your app',
    plainEnglish: "Imagine if a hacker could add a fake 'Reset Password' form to your app that sends your users' passwords to them instead of you. Without a Content Security Policy, that kind of attack is much easier to pull off.",
    fixPrompt: `Add a Content-Security-Policy (CSP) header to my Next.js app. Add it to the headers() section in next.config.js only. Start with a permissive policy: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: 'CSP can break your app if set too strictly. After adding it, test every page — especially any that loads external scripts, fonts, or images.',
  },
  'header-x-frame-options-pass': {
    headline: "Your app can't be embedded in other websites",
    plainEnglish: 'Attackers sometimes embed real websites inside invisible frames on their own malicious pages, then trick users into clicking on the hidden site. Your app is protected against this.',
  },
  'header-x-frame-options-warning': {
    headline: 'Your app could be embedded inside another website without your knowledge',
    plainEnglish: "This is called 'clickjacking'. A hacker could put your entire app in an invisible layer over their site. When users think they're clicking a button on the hacker's page, they're actually clicking buttons on your app — like approving a transfer or deleting their account.",
    fixPrompt: `Add the X-Frame-Options security header to my Next.js app. Add it to the headers() section in next.config.js only. Set the value to "SAMEORIGIN". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: 'After adding this, test that your app still works normally. If you intentionally embed your app in other sites (like an iframe widget), this will break that.',
  },
  'header-x-content-type-options-pass': {
    headline: "Your app tells browsers exactly what type of file each response is",
    plainEnglish: "Browsers can sometimes guess wrong about what type of file they're receiving, which can be exploited. Your app makes this crystal clear so there's no guessing.",
  },
  'header-x-content-type-options-warning': {
    headline: "Browsers might misinterpret files on your site",
    plainEnglish: "If someone uploads a file to your app that pretends to be an image but is actually a script, some browsers might try to run it. This header tells the browser to trust the file type you declare, not guess.",
    fixPrompt: `Add the X-Content-Type-Options security header to my Next.js app. Add it to the headers() section in next.config.js only. Set the value to "nosniff". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: 'This is a low-risk change. Test your app after making it to confirm everything still loads correctly.',
  },
  'header-referrer-policy-pass': {
    headline: 'Your app controls what information it shares when linking out',
    plainEnglish: "When your users click a link to another website, browsers normally share your full URL with that site. Your app limits what gets shared to protect user privacy.",
  },
  'header-referrer-policy-warning': {
    headline: 'Your app might be sharing private URLs with other websites',
    plainEnglish: "When one of your users clicks a link to an external site, their browser silently tells that site 'the user came from [your-app.com/private/user/123/settings]'. If your URLs contain user IDs or private paths, you're leaking that information.",
    fixPrompt: `Add the Referrer-Policy security header to my Next.js app. Add it to the headers() section in next.config.js only. Set the value to "strict-origin-when-cross-origin". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: 'This is a low-risk change. After adding it, test any pages that rely on referrer information (like referral tracking).',
  },
  'header-permissions-policy-pass': {
    headline: "You've restricted which browser features your app can use",
    plainEnglish: "You've told browsers that your app doesn't need access to things like your users' cameras, microphones, or location — so even if someone injects malicious code, they can't activate those features.",
  },
  'header-permissions-policy-warning': {
    headline: "Your app hasn't restricted access to device features",
    plainEnglish: "If someone injects malicious code into your app (through an XSS attack, for example), they could potentially access your users' camera, microphone, or location. This header lets you say 'my app doesn't need any of those things', blocking that attack path.",
    fixPrompt: `Add the Permissions-Policy security header to my Next.js app. Add it to the headers() section in next.config.js only. Set the value to "camera=(), microphone=(), geolocation=(), payment=()". Show me exactly what to add to next.config.js — do not modify any other files.`,
    fixPromptWarning: "If your app genuinely uses the camera, microphone, or payments API, adjust the policy accordingly before applying. Test after making the change.",
  },

  // CORS
  'cors-pass': {
    headline: "Your API can't be called from random other websites",
    plainEnglish: "If someone tries to build a website that secretly makes requests to your API (to steal data or perform actions on behalf of your users), the browser will block it.",
  },
  'cors-warning': {
    headline: 'Any website on the internet can call your API',
    plainEnglish: "Your API is completely open to cross-origin requests. Any website could make requests to your API on behalf of your users — potentially reading their data or performing actions in their name — and the browser wouldn't stop it.",
    fixPrompt: `My Next.js API routes have CORS set to allow all origins (Access-Control-Allow-Origin: *). Fix the CORS configuration to only allow requests from my own domain. Update the API route middleware or next.config.js to set a specific allowed origin instead of '*'. Only modify the CORS configuration — do not change any other logic.`,
    fixPromptWarning: 'After fixing CORS, test that your own frontend can still call your API correctly. If you have legitimate third-party integrations that need API access, list them explicitly in the allowed origins.',
  },

  // Sensitive paths
  'exposure-env': {
    headline: 'Your .env file is publicly accessible',
    plainEnglish: "This is as bad as it gets. Your .env file contains all your app's secret passwords — database credentials, API keys, payment processor secrets. Right now, anyone on the internet can read them. Change every secret in that file immediately.",
    fixPrompt: `My .env file is publicly accessible at the website root. This should never happen. Help me understand why this is exposed and how to prevent it. I am using [your hosting platform]. Only tell me how to secure file access on my hosting platform — do not modify application code.`,
    fixPromptWarning: 'Fixing the exposure is step 1. Step 2 — which you must also do — is rotating every single secret in that file. Assume they have already been compromised.',
  },
  'exposure--env-local': {
    headline: 'Your local environment secrets are publicly accessible',
    plainEnglish: 'Your .env.local file — meant only for your development machine — is visible to anyone on the internet. This likely contains API keys and secrets that should never leave your computer.',
    fixPrompt: `My .env.local file is publicly accessible on my live website. Help me block access to all .env files on [your hosting platform]. Only tell me how to configure file access on the hosting platform — do not modify application code.`,
    fixPromptWarning: 'After blocking access, rotate any secrets that were in the file. Assume they have been seen by others.',
  },
  'exposure--env-production': {
    headline: 'Your production secrets file is publicly accessible',
    plainEnglish: 'Your .env.production file — which contains your live production secrets — is visible to anyone on the internet. This is critical. Rotate every key in this file immediately.',
    fixPrompt: `My .env.production file is publicly accessible on my live website. Help me block access to all .env files on [your hosting platform]. Only tell me how to configure file access on the hosting platform — do not modify application code.`,
    fixPromptWarning: 'After blocking access, immediately rotate all secrets in the file. Treat them as compromised.',
  },
  'exposure--git-config': {
    headline: 'Your Git repository details are exposed',
    plainEnglish: "Your .git folder is publicly accessible. This can reveal your entire code history, commit messages (which often contain hardcoded secrets), branch names, and in some cases allow someone to reconstruct your entire source code. This is a serious leak.",
    fixPrompt: `My .git/config file is publicly accessible on my website. This means my git folder is exposed. Help me block public access to the .git directory on [your hosting platform]. Only tell me how to configure this on the hosting platform — do not modify application code.`,
    fixPromptWarning: 'Check your git commit history for any hardcoded secrets or credentials that may have been committed. Use a tool like git-secrets or truffleHog to scan your history.',
  },
  'exposure--package-json': {
    headline: 'Your app\'s package list is publicly visible',
    plainEnglish: "Your package.json file lists all the software libraries your app uses, including their version numbers. Attackers use this to look up known vulnerabilities in your specific versions — it's like handing them a map of your weaknesses.",
    fixPrompt: `My package.json file is publicly accessible on my live website. Help me block public access to this file on [your hosting platform]. Only tell me how to configure file access on the hosting platform — do not modify any application code.`,
    fixPromptWarning: 'This is a medium-risk fix. Test after applying that your app still builds and runs correctly.',
  },
  'exposure--wp-admin': {
    headline: 'A WordPress admin panel was detected',
    plainEnglish: "We found a WordPress admin login page at /wp-admin. If your app isn't actually WordPress, this could indicate a misconfiguration. If it is WordPress, make sure you're using a strong password and have 2-factor authentication enabled.",
  },

  // API Keys
  'secrets-openai-api-key': {
    headline: 'Your OpenAI API key is exposed in your code',
    plainEnglish: "Your OpenAI key is visible in your app's JavaScript — which means anyone can view it in their browser. They can use it to generate AI text or images and bill it to your account. Rotate this key immediately in your OpenAI dashboard.",
    fixPrompt: `My OpenAI API key is exposed in my frontend JavaScript bundle. Move all OpenAI API calls to a server-side API route so the key is never sent to the browser. Create a new API route at /api/ai that makes the OpenAI call server-side. The frontend should call /api/ai instead of calling OpenAI directly. Only create the new API route file — do not modify any other files.`,
    fixPromptWarning: 'After moving the key server-side, rotate the old key in your OpenAI dashboard immediately. Assume it has been used by others.',
  },
  'secrets-stripe-live-key': {
    headline: 'Your live Stripe payment key is exposed',
    plainEnglish: "This is an emergency. Your Stripe live secret key is visible in your app's frontend code. Anyone who finds it can create refunds, transfer money, read customer payment information, and more — all using your real payment account. Rotate this key in Stripe right now.",
    fixPrompt: `My Stripe live secret key is exposed in my frontend JavaScript. Move all Stripe server-side calls (charges, refunds, customer creation) to a Next.js API route. The key must never appear in frontend code. Create an API route at /api/payments that handles Stripe operations server-side. Only create the new API route file — do not modify any other files.`,
    fixPromptWarning: 'Rotate the exposed Stripe key immediately in your Stripe dashboard before making any code changes. Check your Stripe dashboard for any suspicious transactions.',
  },
  'secrets-stripe-test-key': {
    headline: 'Your Stripe test key is in your frontend code',
    plainEnglish: "Your Stripe test key is visible in your app's code. While test keys can't process real money, having them exposed means your app has structural issues that could also expose live keys. Fix the pattern now before you go live.",
    fixPrompt: `My Stripe test key is exposed in my frontend JavaScript. Move Stripe operations to a Next.js API route so keys are never in the browser. Create an API route at /api/payments that handles Stripe operations server-side. Only create the new API route file — do not modify any other files.`,
    fixPromptWarning: 'Fix this now, before your app goes live with real Stripe keys. The same pattern that exposes test keys will expose live keys.',
  },
  'secrets-google-api-key': {
    headline: 'Your Google API key is exposed in your code',
    plainEnglish: "Your Google API key is visible in your frontend JavaScript. Depending on what services it grants access to, someone could use it to make Google Maps, translation, or other API calls at your expense. Restrict the key's usage in Google Cloud Console and consider rotating it.",
    fixPrompt: `My Google API key is exposed in my frontend JavaScript. In the Google Cloud Console, restrict this API key to only allow requests from my specific domain and only for the specific APIs I use. Show me step by step how to set key restrictions in Google Cloud Console — do not modify any code files.`,
    fixPromptWarning: 'Restricting the key by domain is often sufficient for Google Maps/Places keys that are designed to be used client-side. For server-side keys (like Gemini, Vision API), they must never be in frontend code.',
  },
  'secrets-supabase-url': {
    headline: 'Your Supabase project URL is in your frontend code',
    plainEnglish: "Your Supabase URL is in your JavaScript — but this is actually okay for public Supabase keys (NEXT_PUBLIC_SUPABASE_URL). The URL itself isn't secret. However, make sure your Supabase Row Level Security (RLS) policies are enabled, because that's what actually protects your data.",
    fixPrompt: `My Supabase project URL appears in my frontend code. This is normal for Supabase's anon key setup, but I need to make sure my Row Level Security is enabled. Show me how to check and enable Row Level Security on all my Supabase tables. Only show me Supabase dashboard steps — do not modify any application code.`,
    fixPromptWarning: 'The Supabase URL being public is expected. The real protection is Row Level Security. Make sure RLS is enabled on every table that contains user data.',
  },
  'secrets-supabase-jwt': {
    headline: 'A Supabase authentication token is exposed in your code',
    plainEnglish: "A raw JWT (authentication token) is hardcoded in your JavaScript. Unlike the public anon key, this could be a service role key or a user token that gives full database access — bypassing all your security rules. Rotate any service role keys immediately.",
    fixPrompt: `A Supabase JWT token is hardcoded in my frontend JavaScript. If this is a service_role key, it bypasses all Row Level Security. Move any Supabase service_role operations to a server-side API route. The service_role key must never be in frontend code. Create an API route for the server-side Supabase operation — only create the new API route file, do not modify other files.`,
    fixPromptWarning: 'If this is a service_role key, rotate it in Supabase immediately. It grants full database access with no restrictions.',
  },
  'secrets-next-public-secret': {
    headline: 'A secret or API key was made public by mistake',
    plainEnglish: "Something named SECRET, KEY, or TOKEN in your environment variables starts with NEXT_PUBLIC_ — which means it gets bundled into your frontend JavaScript for anyone to read. NEXT_PUBLIC_ variables are meant for non-secret configuration only. Move this to a server-side variable.",
    fixPrompt: `I have an environment variable that starts with NEXT_PUBLIC_ but contains a SECRET, KEY, or TOKEN. NEXT_PUBLIC_ variables are embedded in the browser bundle. Move this to a server-only environment variable (remove the NEXT_PUBLIC_ prefix) and only access it in API routes or server components. Only modify the specific component or route that uses this variable — do not change other files.`,
    fixPromptWarning: 'After making this change, any frontend code that directly used this variable will break. Make sure you move the usage to a server-side API route first.',
  },

  // Supabase service role key — bypasses ALL RLS
  'secrets-supabase-service-role-key': {
    headline: 'Your Supabase master key is exposed — RLS means nothing',
    plainEnglish: "You have two types of Supabase keys: the anon key (which respects your security rules) and the service role key (which bypasses ALL of them). Your service role key is sitting in your public JavaScript right now. Anyone who finds it has full, unrestricted read/write/delete access to your entire database — every user, every payment, every record — with zero restrictions. This is the worst possible Supabase exposure.",
    fixPrompt: `My Supabase service_role key is exposed in my frontend JavaScript. This bypasses all Row Level Security. Move it to server-side only immediately: 1) Remove it from any frontend code or NEXT_PUBLIC_ variables 2) Only use it in API routes with the secret stored in a non-public environment variable (no NEXT_PUBLIC_ prefix). Create a server-side API route to handle operations that needed the service_role key. Only create or modify server-side files — do not touch any frontend files.`,
    fixPromptWarning: 'Rotate the service_role key in your Supabase dashboard immediately — treat it as fully compromised. Then audit your database for any unexpected changes.',
  },

  // Supabase data exposure
  'supabase-data-exposure': {
    headline: 'Anyone can read your database right now',
    plainEnglish: "We used your public Supabase key — the one that's visible in your JavaScript — to query your live database. Real rows came back. No login required. Row Level Security (RLS) is the Supabase feature that's supposed to stop this, but it's not turned on for these tables. Every user record, every email, every piece of data in these tables is readable by anyone who finds your key.",
    fixPrompt: `My Supabase database tables are publicly readable because Row Level Security (RLS) is not enabled. Enable RLS on the following tables and add a basic policy to only allow users to read their own data. For each table, show me the exact SQL to run in the Supabase SQL Editor: 1) ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY; 2) A SELECT policy that restricts anonymous reads. Only output the SQL commands — do not modify any application code files.`,
    fixPromptWarning: 'Enabling RLS will immediately block all anonymous database access. Test your app thoroughly after applying — you may need to add additional policies to restore legitimate access for logged-in users.',
  },

  // URL Discovery pass
  'url-discovery-pass': {
    headline: 'We mapped out all the pages we could find',
    plainEnglish: "We checked your sitemap, robots.txt, and homepage links to build a picture of your app's structure. Review the list below — some of these pages might surprise you.",
  },
};

export function getCheckCopy(checkId: string, status: string): CheckCopy {
  // Try exact match first
  const exactKey = `${checkId}-${status}`;
  if (checkCopy[exactKey]) return checkCopy[exactKey];

  // Try by just checkId
  if (checkCopy[checkId]) return checkCopy[checkId];

  // Try partial matches for header checks
  for (const [key, val] of Object.entries(checkCopy)) {
    if (checkId.includes(key) || key.includes(checkId)) return val;
  }

  // Fallback
  return {
    headline: 'Security check result',
    plainEnglish: 'See details below.',
  };
}
