---
name: csp-builder
description: Use when adding or tightening a Content Security Policy header for a web app. Walks the actual page, lists every external origin and inline script/style, builds a minimum-viable CSP, and explains every directive in plain terms. Refuses to recommend `unsafe-inline` without naming the concrete reason.
---

# csp-builder

Builds a Content Security Policy header that's tight enough to actually block XSS but doesn't break the app. Generates from real page traffic, not vibes.

## When to use

- Adding security headers to a brand-new app
- Tightening an existing CSP that's mostly `*` and `unsafe-inline` (i.e. doing nothing)
- After a security audit flagged "no CSP" or "weak CSP"
- Before a release where security posture matters (regulated industry, public press, etc.)

## Process

1. **Inventory the actual app surface.** What does each page load? Open the page with devtools Network tab open, or use this in Node:

   ```js
   // capture-csp-sources.mjs — run with puppeteer or playwright
   import { chromium } from 'playwright';
   const b = await chromium.launch();
   const p = await b.newPage();
   const sources = new Set();
   p.on('request', (r) => sources.add(`${new URL(r.url()).origin}`));
   await p.goto('https://your-site.com');
   await p.waitForLoadState('networkidle');
   console.log([...sources].sort().join('\n'));
   await b.close();
   ```

   Get the list of distinct origins per page. That's your starting point for `script-src`, `style-src`, `img-src`, `connect-src`, `font-src`.

2. **Decide on inline policy.** Three options:

   - **Pure CSP, no inline** — best, but means moving every `<script>{ inline JS }</script>` and `<style>{ inline CSS }</style>` to external files. Sometimes impractical for SSR'd apps.
   - **Hash-based inline** — generate SHA-256 hashes of every inline block, put them in `script-src`. Brittle: any change to inline content invalidates the hash, must regenerate on each build.
   - **Nonce-based inline** — server emits a unique random `nonce-XXX` per response, includes it in CSP and on each `<script nonce="XXX">`. Robust, but requires server-side templating.

   **Default recommendation: nonces.** Hash-based for static-only sites; nonces for any SSR.

3. **Draft the header.** Mininum-viable shape:

   ```
   default-src 'self';
   script-src 'self' 'nonce-{NONCE}' https://js.cloudpayments.ru;
   style-src 'self' 'nonce-{NONCE}';
   img-src 'self' data: https://*.your-cdn.com;
   font-src 'self' data:;
   connect-src 'self' https://api.your-site.com wss://your-site.com;
   media-src 'self';
   object-src 'none';
   frame-ancestors 'none';
   base-uri 'self';
   form-action 'self';
   upgrade-insecure-requests;
   ```

   Each directive has a reason:
   - `default-src 'self'` — fallback for unspecified directives
   - `'self'` — your own origin
   - `'nonce-{NONCE}'` — emitted per-response, only-blessed inlines run
   - explicit external origins — only what you actually use
   - `data:` — for inline images/fonts (rare, but common for icons)
   - `object-src 'none'` — blocks `<object>`/`<embed>`, classic XSS vector
   - `frame-ancestors 'none'` — same as `X-Frame-Options: DENY`, prevents click-jacking
   - `base-uri 'self'` — blocks `<base>` injection redirecting all relative URLs
   - `upgrade-insecure-requests` — auto-upgrade `http://` references to `https://`

4. **Generate the nonce server-side per request:**

   Express:
   ```ts
   import crypto from 'node:crypto';
   app.use((req, res, next) => {
     res.locals.nonce = crypto.randomBytes(16).toString('base64');
     next();
   });
   app.use((_req, res, next) => {
     res.setHeader('Content-Security-Policy',
       `default-src 'self'; script-src 'self' 'nonce-${res.locals.nonce}' ...`);
     next();
   });
   ```

   Next.js (middleware.ts):
   ```ts
   const nonce = crypto.randomBytes(16).toString('base64');
   const csp = `script-src 'self' 'nonce-${nonce}' ...`;
   const res = NextResponse.next();
   res.headers.set('content-security-policy', csp);
   res.headers.set('x-nonce', nonce);
   return res;
   ```

5. **Test in report-only mode FIRST.** Don't enforce on day one — you'll break the app:

   ```
   Content-Security-Policy-Report-Only: <your draft>; report-uri /csp-report
   ```

   Add a `/csp-report` endpoint that logs violations. Watch for a few days of real traffic. Fix gaps. **Then** flip to enforce mode by removing `-Report-Only`.

6. **Document the policy.** Markdown file or top-of-file comment listing every external origin and *why*. Future-you won't remember why `https://js.stripe.com` is in `script-src`.

## What NOT to do

- **Don't paste in `'unsafe-inline'`** without writing down the reason. If you must, note: "needed because <X library> emits inline styles. Owner: figure out alternative by Q3."
- **Don't ship `script-src *`** — that's no CSP at all.
- **Don't include `'unsafe-eval'`** unless code in the app actually evaluates dynamic strings (the JS feature CSP `'unsafe-eval'` covers). Most apps don't.
- **Don't enforce CSP on first deploy.** Always Report-Only first. The first enforce-mode CSP always misses 1-2 things in production traffic that you didn't see locally.
- **Don't ship `connect-src 'self'`** if you have third-party APIs (analytics, payment, error reporting). They'll silently break in production.

## Examples

### Tight CSP for a SaaS app (Next.js + Stripe + Sentry)

```
default-src 'self';
script-src 'self' 'nonce-{NONCE}' https://js.stripe.com https://browser.sentry-cdn.com;
script-src-elem 'self' 'nonce-{NONCE}' https://js.stripe.com;
style-src 'self' 'nonce-{NONCE}' 'unsafe-hashes' 'sha256-XXX=';   # one inline style for SSR critical CSS
img-src 'self' data: blob: https://*.stripe.com;
font-src 'self' data:;
connect-src 'self' https://api.stripe.com https://*.ingest.sentry.io wss://your-site.com;
frame-src https://js.stripe.com;
object-src 'none';
frame-ancestors 'none';
base-uri 'self';
form-action 'self' https://hooks.stripe.com;
upgrade-insecure-requests;
report-uri /csp-report
```

Comment block:
```
# Why each external origin:
#   js.stripe.com               — Stripe.js for Elements
#   browser.sentry-cdn.com      — Sentry browser SDK loader
#   api.stripe.com              — Stripe API XHRs
#   *.ingest.sentry.io          — Sentry error reporting POSTs
#   sha256-XXX=                 — inline critical CSS in <head>, regenerated on build
```

## Recovery

- **Existing CSP is `default-src *; script-src *`:** that's permissive equivalent of nothing. Tighten in Report-Only mode for 1 week, then enforce.
- **Third-party widget refuses to work without `unsafe-inline`:** open an issue with the vendor, document the deviation, time-box revisiting it.
- **Reports flooding `/csp-report` from old browsers / extensions:** filter by user-agent before logging, only act on reports from supported browsers.
