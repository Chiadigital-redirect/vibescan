# VibeScan 🛡️

**Security scanner for AI/vibe-coded apps.**

VibeScan helps founders who built their app with Lovable, Bolt, Cursor, V0, or any other AI coding tool to quickly discover common security issues — before their users (or attackers) do.

## What it does

Enter any publicly accessible URL and VibeScan will run a series of **passive checks** (standard HTTP requests only) and return a plain-English security report with:

- 🗺️ **Page discovery** — every URL visible via sitemap, robots.txt, and links
- 🔑 **API key detection** — searches JavaScript bundles for exposed keys (OpenAI, Stripe, Supabase, Google)
- 🛡️ **Security headers** — checks for HSTS, CSP, X-Frame-Options, and more
- 🚪 **Sensitive file exposure** — tests for publicly accessible `.env`, `.git/config`, `package.json`, etc.
- 🌐 **CORS policy** — detects wide-open CORS that lets any site call your API
- 🔒 **SSL/HTTPS** — verifies your site uses encrypted connections

Every finding includes:
- A plain-English headline ("Your API key is exposed in your code")
- A simple explanation ("Anyone can read your OpenAI key and run up your bill")
- A severity rating (🔴 urgent / 🟡 warning / 🟢 pass)
- A ready-to-use **fix prompt** you can paste into Lovable, Cursor, Bolt, or ChatGPT

## What it does NOT do

- ❌ No penetration testing or active exploitation
- ❌ No authentication bypass attempts
- ❌ No SQL injection, XSS probing, or fuzzing
- ❌ No rate-limit hammering or stress testing
- ❌ No modification of your app or data
- ❌ No storage of scan results (scans are completely stateless)

VibeScan only reads what any ordinary browser would read. **You should only scan sites you own or have permission to scan.**

## Stack

- **Framework:** Next.js 14 (App Router)
- **Styling:** Tailwind CSS
- **Deployment:** Vercel
- **Auth/DB:** None required — all scans are stateless

## Getting started

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Build for production
npm run build
```

No environment variables required for the MVP.

## Design philosophy

VibeScan is designed for **non-technical founders**, not security professionals. Every finding is explained in plain English, and fix prompts are written specifically for AI coding tools (Lovable, Cursor, Bolt, ChatGPT).

The design is light, clean, and friendly — not a dark-mode hacker terminal.

## By

Built by [Creative Digital Group](https://creativedigital.group).
