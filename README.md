# x402guard

**Security scanner for x402 / agent-payment integrations.** It finds the bugs that live in the **web↔chain glue** — the part general Solidity scanners (Slither, MythX) don't look at: replay, allowance, idempotency, unauthenticated treasury broadcast, SSRF webhooks, fail-open auth, predictable IDs.

Zero dependencies. Runs anywhere Node ≥18 runs. CLI + GitHub Action + HTML/JSON reports.

```bash
node bin/x402guard.js ./my-x402-project --html report.html
```

---

## Why this exists

x402 is being adopted fast (Coinbase + the x402 Foundation: Stripe, Cloudflare, AWS, Google, Visa, Mastercard) — but **agent-payment code moves real USDC over a brand-new attack surface**, and real money is already being lost (GoPlus flagged x402-token exploits that drained 200+ wallets). The academic taxonomy is already published: *"Five Attacks on x402"* (arXiv:2605.11781) — replay, allowance bypass, web-layer idempotency, authorization/binding.

The catch: **>80% of deployed contracts never get a professional audit**, and the existing tools check the *contract*, not the *integration*:

| Tool | Checks | Misses |
|------|--------|--------|
| Slither / MythX / Echidna | Solidity contract internals | the x402 web↔chain glue |
| OpenZeppelin Defender / Forta | runtime monitoring (general) | x402-specific flows |
| AgentLISA / SmartSec | general AI contract scans | x402-vuln specialization |

**x402guard sits in that gap:** the integration-layer ruleset, runnable in CI, free at the entry point.

---

## What it checks (v0.1 — 15 rules)

| ID | Sev | What |
|----|-----|------|
| `X402-BROADCAST-NO-AUTH` | critical | Server endpoint signs+broadcasts a tx with no HMAC/signature check |
| `X402-HARDCODED-SECRET` | critical | Private key / mnemonic / live key in source (excludes zero-sentinels) |
| `X402-REPLAY-NO-NONCE` | high | Settlement handler with no replay/nonce protection (Five Attacks #I) |
| `X402-IDEMPOTENCY` | high | Payment callback/webhook with no exactly-once guard (Five Attacks #II) |
| `X402-FAILOPEN-SECRET` | high | Auth skipped when its secret env var is unset (fails open) |
| `X402-SSRF-WEBHOOK` | high | Outbound request to a dynamic/user URL with no SSRF guard |
| `SOL-REENTRANCY` | high | Exposed value-moving function without `nonReentrant` |
| `SOL-TX-ORIGIN-OWNER` | high | `tx.origin` used (often deploy owner) — hot-EOA risk |
| `SOL-RAW-ERC20` | medium | Raw ERC20 transfer (not SafeERC20) |
| `SOL-UNLIMITED-APPROVAL` | medium | `type(uint256).max` allowance (Five Attacks #III) |
| `SOL-PRIVILEGED-NO-MODIFIER` | medium | Privileged setter with no access modifier |
| `X402-WEAK-RANDOM` | medium | `Math.random()` for an id/token/nonce |
| `X402-STACKTRACE-LEAK` | medium | Stack trace / raw error returned in an HTTP response |
| `X402-CORS-WILDCARD` | low | Wildcard CORS on sensitive endpoints |
| `X402-INMEM-RATELIMIT` | low | In-memory rate limiter (useless on serverless) |

Each finding includes file:line, why it matters, a concrete fix, and a reference (Five Attacks / SWC / CWE / OWASP).

---

## Case study: scanning a live mainnet escrow backend

Dogfooded against a production agent-escrow codebase (140 files):

```
GRADE F  (0/100)
critical 2   high 13   medium 9   low 2
```

It automatically reproduced the headline findings of a manual audit, including a **live unauthenticated treasury-broadcast path** (`api/post-work-v2.js:275`), a committed test private key, fail-open `CRON_SECRET` checks, an SSRF-able webhook deliverer, and `tx.origin`-owned deploy scripts — in under a second, with zero config.

---

## Usage

```bash
# scan a directory, fail CI on critical/high
node bin/x402guard.js .

# write reports
node bin/x402guard.js . --html report.html --json report.json

# don't fail the build (report-only)
node bin/x402guard.js . --no-gate
```

Exit code is `1` when any critical/high finding is present (CI gate), else `0`.

### CI

Add this workflow to fail the build on any critical/high finding:

```yaml
name: x402guard
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx x402guard . --json x402guard-report.json
```

Use `--exclude <substr>,<substr>` to skip paths (e.g. vendored code or fixtures).

### Tests

```bash
npm test   # scans __fixtures__ and asserts rules fire on vuln code, stay silent on hardened code
```

---

## Honest limitations

- **Heuristic static analysis, not a proof.** It finds patterns; it will have false positives and false negatives. Verify each finding.
- **It complements, it does not replace, a professional smart-contract / ZK audit and a bug bounty.** Use it as the continuous/CI layer *before* and *between* audits.
- Reentrancy detection is intentionally conservative (only exposed functions with direct value moves) to keep the signal-to-noise high; deep call-graph reentrancy still needs Slither + a human.

---

## Roadmap

- v0.2: SARIF output (GitHub code-scanning), npm publish (`npx x402guard`), config file for rule tuning/baselines.
- v0.3: ERC-8004 identity/reputation checks; x402 V2 ruleset; allowance-scope dataflow.
- v1.0: **runtime monitoring** — an x402-aware alerting layer (the recurring-revenue counterpart to OZ Defender) that watches live agent-payment flows for replay/drain/anomalous allowance.

## License

MIT.
