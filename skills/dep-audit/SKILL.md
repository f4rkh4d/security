---
name: dep-audit
description: Use to triage dependency vulnerabilities (npm audit / cargo audit / pip-audit). Distinguishes real impact from CVE-noise — checks if the vulnerable code path is actually reached, ranks by exploitability, and proposes minimal-blast-radius upgrade plans.
---

# dep-audit

Most "audit" tools dump a list and walk away. This walks the list with you, separates "actually exploitable in our codebase" from "CVE-noise", and writes the upgrade plan.

## When to use

- After `npm audit`, `pnpm audit`, `cargo audit`, `pip-audit`, `bundler-audit`
- Before a release, as part of release-checklist
- When a security bot opens a flood of PRs and you need to triage

## Process

1. **Run the audit.** Use the project's package manager — don't pick. Capture full JSON output:

   ```sh
   npm audit --json > /tmp/audit.json
   cargo audit --json > /tmp/audit.json
   pip-audit --format json > /tmp/audit.json
   ```

2. **Parse and categorize.** For each vulnerability:

   ```
   id: CVE-2024-12345 | GHSA-...
   package: lodash@4.17.10
   path: app -> express -> body-parser -> lodash    # how it's pulled in
   severity: high
   patched-in: ≥4.17.21
   advisory: <one-line description>
   ```

3. **For each, check exploitability.** This is the high-leverage step:

   - **Direct dep** — your code might call the vulnerable function
   - **Transitive dep** — your code never imports it; only used by N libs deep
   - **Vulnerable function** — does the advisory name a function/class? `grep -r 'vulnerableFn(' src/`
   - **Reachable from request handlers?** Walk imports from each route handler. If the vulnerable code is in dev-tools / build-time only, severity drops.
   - **CVSS attack vector** — Network/Local/Adjacent? UI/UX-only impact (e.g. ReDoS in a CLI flag) is lower priority.

   Produce a triage table:

   ```
   PRIORITY  CVE         PATH                                  REACHABLE  ACTION
   -----------------------------------------------------------------------------------------------
   p0        GHSA-1234   express → body-parser → qs            YES         upgrade body-parser to ≥1.20.3
   p1        CVE-5678    eslint-plugin-x → tar                 NO (devOnly) upgrade at next routine bump
   p2        GHSA-aaaa   ws (used in test fixture only)        NO          ignore, document why
   p3        CVE-bbbb    semver < 7.5.2 (used by build-tool)   NO          ignore, devDep
   ```

4. **Propose the upgrade order.** For p0/p1:

   - **Smallest-radius first.** Bumping a leaf dep often resolves several upstream advisories.
   - **Major version bumps separately.** `semver: ^6 → ^7` is its own PR with breaking-change scan.
   - **Lockfile-only fixes** when possible: `npm audit fix` (not `--force`), `cargo update -p <crate>`. Avoid `--force` — it'll happily break your app.

5. **For each upgrade, propose a verification:**

   ```
   - upgrade body-parser ^1.18.0 → ^1.20.3
     verify: bun test, hit POST /api/* once with a large body, watch for 413 changes
   - upgrade tar ^4 → ^6 (major)
     verify: confirm npm scripts that extract tarballs still work; check streaming API didn't break
   ```

6. **Output the actionable list and a deferred list.** Don't auto-apply.

## What NOT to do

- **Don't run `npm audit fix --force`** — that bumps majors, often breaks the build, and security bots will reopen the same PR next week. Always do controlled upgrades.
- **Don't trust severity blindly.** A "critical" in a build-time dep is a p2 at best; a "moderate" in a request-path dep can be p0.
- **Don't suppress with `audit-resolve` / `npm-shrinkwrap` overrides** unless documented and time-boxed.
- **Don't propose npm/yarn migration** as a fix. Different bug.
- **Don't ignore unreachable-but-published** advisories without writing down the reasoning. Comment in `package.json` under a `// NOTE:` or in a `SECURITY.md`.

## Examples

### Real-life triage output

```
3 advisories, 1 actionable, 2 deferred.

p0  GHSA-rrqm-p22r-vrh9   path-to-regexp 6.2.x → 6.3.0
    Used by: express → routing layer for our /api/* requests.
    Vulnerable fn `pathToRegexp(input)` reachable.
    fix: upgrade express to ^4.21 (pulls path-to-regexp 6.3 transitively)
    verify: bun test; hit a few API routes with deeply-nested paths

p2  CVE-2024-21536        semver < 7.5.2 in eslint-plugin-x
    devDep only. ESLint runs at dev/CI. No prod surface.
    defer: bundle into next routine "chore: bump dev deps" PR.

p3  GHSA-bbbb-cccc-dddd   ws < 8.17 in @types/jest fixture
    test-only. Not reachable from any non-test path.
    defer: ignored. Documented in SECURITY.md.
```

### Rejection of audit fix --force

```
You: "can you run npm audit fix --force?"
me: "No. Three of the seven 'fixes' bump majors:
       - express 4 → 5 (breaking middleware changes)
       - jsonwebtoken 8 → 9 (algorithm whitelist behavior changed)
       - typescript 4 → 5 (your tsconfig has flags that 5 dropped)
     I'll propose each upgrade as a separate PR with verify steps."
```

## Recovery

- **No package manager detected:** Ask which one. Don't guess.
- **Audit tool errors out** (lockfile out of sync, network issue): fix that first, document it. Don't skip the audit.
- **Hundred+ advisories, mostly transitive noise:** triage by depth — only direct deps and 1-hop deep get attention; flag a "lockfile cleanup" PR for the long tail.
