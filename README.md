# security

4 skills for the security side of building software. Installable via [skl](https://github.com/f4rkh4d/skl) or by hand.

| skill | what it does |
|---|---|
| `/dep-audit` | triage `npm audit` / `cargo audit` / `pip-audit` output by real exploitability |
| `/secret-scan` | scan staged diff or repo for committed secrets, action plan included |
| `/csp-builder` | build a CSP from the app's actual loaded origins, with nonce-based inline + rollout via Report-Only |
| `/auth-review` | review auth code for concrete vulns (JWT alg, session storage, rate limiting, IDOR) |

## install

```sh
skl install f4rkh4d/security
```

## why these four

every dev has a "ugh, security" moment per quarter — usually triggered by a tool dump (npm audit), a leaked secret, an audit firm's report, or a "is our auth even right?" gut check. these four skills are the tight, opinionated paths through each.

each skill cites real code, names real CVEs/files/lines, refuses generic best-practice lectures.

## license

MIT
