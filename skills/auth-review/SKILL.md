---
name: auth-review
description: Use when reviewing an authentication / session implementation before shipping. Walks the actual code (login, logout, token issuance, session storage, password reset, account takeover paths) and flags concrete vulnerabilities. Refuses to claim "looks fine" — every claim is backed by a code citation.
---

# auth-review

Reviews the auth code for concrete vulnerabilities. Goes file-by-file, route-by-route. Outputs findings, not vibes.

## When to use

- Before shipping a new auth system to prod
- After a contractor/colleague writes the auth module
- After a security audit report mentions auth weaknesses
- During incident response if you suspect account takeover

## Process

1. **Map the auth surface.** Find every route/handler involved:

   - **Identify**: login, signup, logout
   - **Verify**: SMS code verify, magic-link verify, OAuth callback, JWT verify
   - **Manage**: password reset request, password reset confirm, email change, 2FA enroll/verify
   - **Bypass paths**: API tokens, service-to-service auth, admin impersonation

   For each, note: route, handler file, what it returns on success, what it returns on failure.

2. **Check session storage.** Three questions per session:

   - **Where stored?** Cookie / localStorage / sessionStorage. Cookie is the only safe-by-default choice for sensitive sessions. localStorage = readable by any JS = XSS-game-over.
   - **Cookie attributes?** `HttpOnly` (must), `Secure` (must in prod), `SameSite=Lax` (default), `Path=/`, `Domain` carefully chosen.
   - **Session token format?** Random opaque (good), JWT (acceptable but watch for algo-confusion), encoded user-id (terrible).

3. **Token issuance specifics.**

   For each token type:

   - **Length?** Random tokens should be ≥128 bits of entropy. `randomBytes(32).toString('base64url')` = 256 bits ✓. `Math.random().toString(36)` = compromised.
   - **Hashing for storage?** Tokens stored in DB should be hashed (`SHA-256` is fine, no salt needed since input is high-entropy). On lookup, hash the cookie value and compare.
   - **TTL?** Reasonable: 30 days for "remember me", 24 hours for new auth, 5 minutes for reset codes.
   - **Revocation path?** A way to invalidate a session before TTL.

4. **Password specifics** (if passwords are used):

   - **Hashing**: bcrypt (cost ≥12), argon2id, or scrypt. Never SHA, MD5, plain text, or AES.
   - **Length validation**: minimum 10 chars; reject explicit-blocklist of top-1000 leaked passwords.
   - **Reset flow**: never email the password back; send a one-time link with a hashed token, TTL ≤1 hour, single-use.

5. **Rate limiting.** Test by reading the middleware:

   - **Login attempts per IP**: ≤10/min recommended
   - **Login attempts per username**: ≤5/min independently of IP (defends distributed brute-force)
   - **SMS code requests per phone**: ≤1/60s (also defends against $$ burn through SMS provider)
   - **Password reset requests per email**: ≤3/hour

   If the project has no rate limiter, that's a finding.

6. **Authorization** (separate from authentication):

   - **Tenant scoping**: does each request honor `current_user.tenant_id`? Look for `WHERE tenant_id = ` or RLS policies.
   - **Role checks**: are admin endpoints behind a role check? Look for `requireRole('admin')` middleware.
   - **IDOR**: `/api/users/:id` — does it verify the requester can access user :id, or does it trust the URL?

7. **Common bugs, search aggressively for each:**

   | bug | grep |
   |---|---|
   | Plaintext passwords in DB | `password.*=.*body\.|password.*=.*req\.` (without hash function) |
   | JWT alg-none / alg-confusion | `verify.*algorithms.*\[\]|verify.*\{ algorithm: 'none'` |
   | SQL injection in login | string concat into queries: `query.*\+.*username\|email` |
   | Timing-unsafe compare | `password === |token === |hash === ` (should be `timingSafeEqual`) |
   | Cookie with no HttpOnly | `setCookie.*httpOnly:\s*false|res.cookie.*\)$` (no opts) |
   | Reset token reuse | reset endpoint that doesn't delete the token after use |
   | Open redirect on login | `res.redirect.*req\.query|res\.redirect.*req\.body` (with no allowlist) |
   | Verbose error revealing user existence | "user not found" vs "wrong password" — should be the same message |

8. **Output format.** Per finding:

   ```
   FINDING: <short title>
   Severity: critical | high | medium | low
   File: src/auth/login.ts:42
   Issue: <one paragraph>
   Reproduction: <curl command or sequence>
   Fix: <concrete code change, ideally a snippet>
   ```

9. **Final verdict.** A summary: critical count, high count, medium count, low count. **Not** a "looks good overall" line. Auth is binary — there are bugs, or there aren't.

## What NOT to do

- **Don't approve "secure enough" designs that emit JWT in localStorage** because the team is "comfortable with it". Cookie + HttpOnly is non-negotiable for browser sessions.
- **Don't trust the framework defaults blindly.** Express default cookie has no flags. Next.js cookies need explicit options. Always read the actual code.
- **Don't skip the password-reset flow.** It's where most account-takeover vulns live.
- **Don't accept "we'll add rate-limiting later."** It's the most common omission and the easiest to exploit.
- **Don't generate fake CVEs / fake CVSS scores** for findings. Describe the impact in plain words.

## Examples

### Critical finding

```
FINDING: JWT verifier accepts alg=none
Severity: critical
File: src/middleware/auth.ts:15

Code:
  const payload = jwt.verify(token, SECRET);

Issue: jwt.verify with no `algorithms` arg lets `{alg: 'none'}` tokens
through. Attacker forges any user_id with a one-line bash:
  echo -n '{"alg":"none","typ":"JWT"}' | base64
  echo -n '{"sub":"admin"}' | base64
  → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

Reproduction:
  curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." /api/admin
  → 200 OK (should be 401)

Fix:
  jwt.verify(token, SECRET, { algorithms: ['HS256'] })
```

### Medium finding (rate limiting absent)

```
FINDING: No rate limiting on /auth/request-code
Severity: medium
File: apps/api/src/routes/auth.ts:14

Issue: handler issues SMS via Mobizon on every call, no per-phone or
per-IP rate limit. Cost: ~5₸ per SMS × unlimited calls = unbounded
liability. Also enables SMS-bombing of any phone number.

Fix:
  Add a per-phone limiter (1 SMS / 60s) and per-IP (5 / hour) before
  notifier.sms.send. Existing rate-limit.ts utility can be reused.
```

## Recovery

- **Codebase is huge, can't review everything:** start with the routes that issue / verify session tokens. That's where 80% of bugs are.
- **Auth is via a third-party provider (Auth0, Clerk):** narrower review — verify the wiring, redirect URIs, claim trust. Most bugs there are configuration, not code.
- **You find something critical:** stop the review, write that finding, get the user to fix it before continuing. Don't bury it in a list.
