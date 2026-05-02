---
name: secret-scan
description: Use to scan a repo (or staged changes) for committed secrets — API keys, tokens, private keys, .env contents pasted into source. Distinguishes high-confidence patterns (AWS access keys, GitHub PATs, JWT secrets) from low-signal heuristics. Outputs an action plan, not a noisy regex dump.
---

# secret-scan

Scans for secrets that have been (or are about to be) committed. Uses well-known prefix patterns first, falls back to entropy heuristics for unknown formats. **Doesn't dump every base64 string in the repo.**

## When to use

- Pre-commit, before a `git commit -a` that the user is unsure about
- After an "I think I leaked something" moment
- Periodic: monthly hygiene check on the repo
- After a junior dev's first PR, defensively

## Process

1. **Decide scope.**

   - **Staged changes** (most common): `git diff --staged` — scan only what's about to be committed.
   - **HEAD vs branch base**: `git diff main...HEAD` — scan a feature branch.
   - **Full repo, current state**: `git ls-files` then read each — what's currently in.
   - **Full history**: every commit since beginning. Slow. Use [trufflehog](https://github.com/trufflesecurity/trufflehog) or `git log -p` + grep. Last resort.

2. **Run high-confidence patterns first.** These have near-zero false-positive rate:

   | secret type | regex | length |
   |---|---|---|
   | AWS Access Key ID | `AKIA[0-9A-Z]{16}` | 20 chars, fixed prefix |
   | AWS Secret Access Key | `aws_secret.*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?` | 40 chars after key |
   | GitHub PAT (classic) | `ghp_[A-Za-z0-9]{36}` | 40 chars, prefix |
   | GitHub fine-grained PAT | `github_pat_[A-Za-z0-9_]{82,255}` | long, prefix |
   | OpenAI key | `sk-(proj-)?[A-Za-z0-9]{48,}` | prefix |
   | Anthropic key | `sk-ant-[A-Za-z0-9-_]{80,}` | prefix |
   | Google API key | `AIza[0-9A-Za-z_-]{35}` | prefix |
   | Stripe live secret | `sk_live_[0-9A-Za-z]{24,}` | prefix |
   | Slack bot token | `xox[baprs]-[0-9-]{10,}` | prefix |
   | RSA/SSH private keys | `-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----` | header line |
   | JWT (suspicious in source) | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | three b64 parts |

   ```sh
   git diff --staged | grep -nE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-ant-...'
   ```

3. **Then entropy/heuristic patterns** (more noise, run scoped):

   - Any `*.env` not gitignored
   - String literals matching `password|secret|api_key|token` followed by `=`/`:` and a value ≥20 chars
   - `*.pem`, `*.p12`, `*.key` files
   - Hardcoded localhost SQL passwords (`postgres://user:password@`)

   These need human review — flag them, don't auto-classify as critical.

4. **For each hit, classify:**

   ```
   FILE                     LINE  KIND               CONFIDENCE  ACTION
   ----------------------------------------------------------------------
   src/config.ts            42    AWS access key     high        rotate now, remove from history
   .env                     -     env file           high        gitignore + verify rotation
   tests/fixtures/jwt.txt   1     JWT                med         likely test fixture, verify
   src/utils/hash.ts        17    base64 string      low         likely a hash constant, no action
   ```

5. **Action plan, ordered:**

   ### a) If the secret IS real and the commit is staged but NOT pushed:
   ```sh
   # Unstage, remove the secret, restage
   git reset HEAD <file>
   $EDITOR <file>          # remove the literal value, replace with env var
   git add <file>
   ```

   ### b) If already pushed to a public/forked-to-public repo:
   - **Rotate the secret immediately.** Don't try to scrub history first — rotation is faster than rewriting and pushing across forks.
   - Then optionally rewrite history with `git filter-repo` and force-push.
   - Notify anyone who might have cloned (CI runners, teammates).

   ### c) If the .env file is committed but only to a private repo:
   - Rotate anyway (someone might have access logs).
   - `git rm --cached .env`, add to `.gitignore`, commit.
   - Move secrets to env-var management (1Password, Vault, GitHub Secrets, etc.).

6. **Add a guard.** A pre-commit hook that re-runs this scan:

   ```sh
   # .git/hooks/pre-commit (or via husky / lefthook)
   #!/usr/bin/env bash
   if git diff --cached | grep -qE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-ant-'; then
     echo "Secret-like pattern in staged diff. Aborting commit."
     exit 1
   fi
   ```

## What NOT to do

- **Don't grep for `password`** alone and call it a day. False positives drown real signal.
- **Don't tell the user "remove it from git history"** as the first action. **Rotate first** — history rewrites take time during which the leaked secret stays valid.
- **Don't suggest BFG / git filter-repo** without warning that it rewrites every collaborator's history. They need to re-clone.
- **Don't ignore `.env.example`** — those are safe and should be committed (with placeholder values). But always verify.
- **Don't run history scans on `node_modules/` or `dist/`** — wastes time on third-party noise.

## Examples

### Real triage

```
scanning git diff --staged...

3 high-confidence hits:
  src/services/email.ts:23   sendgrid api key (SG.xxxx, 22 chars)
  src/config.ts:8            AWS access key (AKIAIOSFODNN7EXAMPLE)
  scripts/deploy.sh:14       hardcoded ssh password

action plan:
  1. ROTATE NOW (not later):
     - SendGrid: dashboard → API Keys → revoke + create new
     - AWS: IAM console → access keys → deactivate + delete
     - SSH: change the deploy server password
  2. Remove from staged files, replace with env-var reads
  3. After commit, audit: have these creds been used since the leak window?
  4. (If pushed) rewrite history via git-filter-repo
```

### False-positive avoidance

```
src/utils/encode.ts:14
  const TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

This matched the entropy heuristic. It's the standard base64 alphabet — not a secret. Skipping.
```

## Recovery

- **Can't tell if a string is a real key or a fixture:** ask the user. If unsure, treat as real → rotate.
- **Repo has a hundred low-confidence hits:** run high-confidence pass first, hand that to the user as a tight list. The long tail is a separate cleanup project.
- **Secret is in CI logs after a failed run:** the log's still in GitHub Actions artifacts → rotate, then ask GitHub support to scrub the log if sensitive.
