---
name: cookie-audit
description: Use when reviewing the cookies a web app sets — checks each one for HttpOnly, Secure, SameSite, Path and Domain scoping, expiration policy, and prefix usage. Outputs a per-cookie verdict with the concrete attribute string the app should be sending. Refuses "cookies are fine" without per-cookie evidence.
---

# cookie-audit

Cookies are how most browser sessions break. The default attributes are unsafe, frameworks set them inconsistently, and a single missing flag turns into account takeover. Audit them per cookie, not as a category.

## When to use

- Pre-launch security review, especially first time you add auth
- A pen-tester report mentioned "session cookie issues" and you want to find the rest
- Before turning on a new auth provider (OAuth, SAML, Clerk, Auth0) — verify what it sets
- Reviewing a PR that touches `Set-Cookie` or session middleware

## Process

1. **Enumerate every cookie the app sets.** Three sources to check:

   ```sh
   # server-side Set-Cookie
   git grep -nE "setCookie|set_cookie|res\.cookie|reply\.setCookie|cookies\.set"

   # framework-specific session middleware
   git grep -nE "express-session|cookie-session|fastify-cookie|iron-session|next-auth"
   git grep -nE "session\(|SessionStore|SessionStrategy"

   # client-side (already a smell — should they be HttpOnly?)
   git grep -n  "document.cookie"
   ```

   Then in the running app, open DevTools → Application → Cookies, list every cookie under your domain. Frameworks often set ones the code doesn't show: csrf tokens, locale, theme, analytics IDs.

2. **For each cookie, verify the five attributes:**

   | attribute | expected value | why |
   |---|---|---|
   | `HttpOnly` | `true` for any auth/session cookie | blocks JS read; defends against XSS-stealing-the-session |
   | `Secure` | `true` always in production | blocks transmission over plain HTTP; mandatory if SameSite=None |
   | `SameSite` | `Lax` for sessions, `None` only when cross-site needed (and `Secure` set) | blocks CSRF; default in modern browsers but be explicit |
   | `Path` | `/` for app-wide, narrower if scoped | unintended path access otherwise |
   | `Domain` | usually unset (host-only) | setting this widens scope to subdomains; opt in only if needed |
   | `Expires` / `Max-Age` | bounded (30 days for "remember me", 1 day for short sessions, session-only for sensitive) | unbounded = stolen cookie valid forever |

3. **Flag the common misconfigurations:**

   - **No `HttpOnly` on a session cookie** → critical. Any XSS = full account takeover. Fix: add `HttpOnly`. Check the framework defaults — Express's `res.cookie()` defaults to NOT setting it.
   - **No `Secure` in prod** → high. Network attacker can sniff. Often happens because the dev environment runs on HTTP and the same code path runs in prod. Fix: set `Secure` based on `process.env.NODE_ENV === 'production'`.
   - **`SameSite=None` without a real reason** → medium-high. Reduces CSRF defence. Common cause: someone copied "fix" from Stack Overflow when iframe embedding broke. Audit whether the embedding actually exists; if not, switch to `Lax`.
   - **`SameSite=None` without `Secure`** → broken; modern browsers reject it. Fix both.
   - **No `Max-Age`/`Expires` on a session cookie** → medium. Cookie persists forever in browser; if the device is shared, anyone gets in. Fix: add a sane max-age.
   - **Wide `Domain` (e.g., `.example.com`) when `app.example.com` is the only consumer** → medium. Subdomains can read the cookie. If you don't run other subdomains, set host-only (omit `Domain`). If you do, audit whether each is trustworthy enough.
   - **Path narrower than `/`** is rarely a security win and usually a bug. Audit case-by-case.

4. **Use cookie name prefixes for defence-in-depth.**

   - `__Secure-` prefix → browser refuses to set unless `Secure` is on
   - `__Host-` prefix → browser requires `Secure`, `Path=/`, and forbids `Domain` (host-only)

   Renaming `session` → `__Host-session` is a one-line change that hard-locks the safest attribute set in place; even if a future config change drops `Secure`, the browser will refuse to set the cookie at all rather than fall back to insecure.

5. **For OAuth / OIDC flows specifically:**

   - The state cookie (CSRF defence on the callback) must be `HttpOnly`, `Secure`, `SameSite=Lax`, `Max-Age=600` (10 minutes is plenty)
   - The PKCE verifier cookie has the same requirements
   - The post-login session cookie is the long-lived one with the rules above
   - All three should be different cookies. Don't reuse names across flows.

6. **Output format:** per cookie:

   ```
   COOKIE: <name>
   Set by: <file:line>
   Current: HttpOnly=? Secure=? SameSite=? Path=? Domain=? Max-Age=?
   Verdict: ok | warn | bad
   Fix: <minimal change to make it safe>
   ```

7. **Verify the fix in production.** After deployment, `curl -I https://app.example.com/login` and inspect the `Set-Cookie` headers in the response. Don't trust the code alone; CDNs, reverse proxies, and edge workers can mutate headers. The browser DevTools view is the source of truth.

## What NOT to do

- **Don't trust framework defaults.** Express's `res.cookie()` doesn't set HttpOnly by default. Next.js's session helpers vary by version. Always be explicit; never depend on the default.
- **Don't set `SameSite=None` "to be safe".** It's the loosest setting; you only want it when you genuinely need cross-site cookie transmission (third-party iframe embedding, federated auth across origins). Default to `Lax`.
- **Don't put auth tokens in `localStorage` to avoid cookie complexity.** localStorage is readable by any JavaScript on the page; one XSS = full account takeover with no `HttpOnly` to save you. Cookies are safer despite the boilerplate.
- **Don't skip the audit because "we use a session library."** Libraries set defaults that change between major versions. Pin and verify.
- **Don't combine `Domain=.example.com` with sensitive cookies if you allow user-controlled subdomains.** A user-uploaded site at `user.example.com` could read your auth cookies.

## Examples

### Real audit output

```
COOKIE: connect.sid
Set by: src/server/index.ts:42 (express-session)
Current: HttpOnly=true Secure=false SameSite=Lax Path=/ Domain=(unset) Max-Age=86400
Verdict: BAD (Secure must be true in production)
Fix:
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 86400000,  // 24h
  }
  Optional upgrade: rename to __Host-session for browser-enforced safety.

COOKIE: locale
Set by: src/middleware/locale.ts:12
Current: HttpOnly=false Secure=false SameSite=(unset) Path=/ Domain=(unset) Max-Age=31536000
Verdict: ok (non-sensitive, but SameSite=Lax is still cleaner)
Fix:
  Set SameSite=Lax explicitly so future browser defaults don't change behaviour.

COOKIE: csrf_token
Set by: src/auth/login.ts:67
Current: HttpOnly=true Secure=true SameSite=None Path=/ Max-Age=3600
Verdict: WARN (SameSite=None reduces CSRF protection without an embedding use case)
Fix:
  If you don't embed login in third-party iframes, switch to SameSite=Lax.
  If you do (e.g. some payment provider iframes), document the reason in code.
```

### Set-Cookie header sanity check (post-deploy)

```sh
curl -sI https://app.example.com/login | grep -i set-cookie
# Set-Cookie: __Host-session=abc123; Max-Age=86400; Path=/; HttpOnly; Secure; SameSite=Lax
```

That's the line you want to see for the primary session cookie. Anything missing in that string is a finding.

## Recovery

- **Codebase has dozens of cookies, can't audit each:** sort by HttpOnly status (easiest grep). Audit every cookie that is NOT HttpOnly first; those are the ones any XSS instantly compromises. Cookies that are already HttpOnly are a second-pass concern.
- **Auth provider sets cookies you can't control:** read their docs for the attributes they set. Auth0, Clerk, NextAuth, Supabase Auth — each has a config option for the cookie behaviour. If they don't expose the config, that's a vendor risk you should escalate.
- **Cookies set by a CDN/edge worker:** the `Set-Cookie` you see in the browser is what the user gets, regardless of what your origin sends. Audit the edge layer separately.
