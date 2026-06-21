// VENDORED COPY of src/rules.js for the serverless deployment — keep in sync with the CLI ruleset.
'use strict';
// x402guard-disable-file — this file documents vulnerable example patterns; the scanner skips it.
// x402guard ruleset — focused on the x402 / agent-payment INTEGRATION layer
// (the web<->chain glue) that general Solidity scanners (Slither/MythX) miss,
// plus the bug classes from "Five Attacks on x402" (arXiv:2605.11781) and
// real incidents (GoPlus x402-token drains). detect(ctx) -> [{line, snippet}].

const norm = p => p.replace(/\\/g, '/');
const rel = ctx => norm(ctx.rel || ctx.path);            // path relative to scan root
const code = ctx => ctx.code || ctx.text;                 // comment-stripped source
const inApi = ctx => /(^|\/)api\//.test(rel(ctx));
const inContracts = ctx => /(^|\/)contracts\//.test(rel(ctx));
// CLI tools / SDKs / examples / deploy scripts legitimately hold keys — not server endpoints.
const isClientSide = ctx => /(^|\/)(bin|sdk|examples?|scripts?|script|tests?|e2e|mocks?)\//.test(rel(ctx));
const isHandler = ctx =>
  inApi(ctx) ||
  /export\s+default\s+(async\s+)?function|module\.exports\s*=\s*async|\(\s*req\s*,\s*res\s*\)|res\.(status|json|send)\(/.test(code(ctx));

const linesMatching = (lines, re, extra) => {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (re.test(l) && (!extra || extra.test(l))) out.push({ line: i + 1, snippet: l.trim().slice(0, 150) });
  }
  return out;
};
const firstLine = (lines, re) => {
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return [{ line: i + 1, snippet: lines[i].trim().slice(0, 150) }];
  return [];
};

// Heuristic: external/public Solidity functions that move value but aren't reentrancy-guarded.
function solUnguardedValueMove(ctx) {
  if (!inContracts(ctx)) return [];
  const { lines } = ctx;
  const out = [];
  const valueMove = /safeTransfer(\(|From\()|\.call\{\s*value/;
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/\bfunction\b/.test(l)) {
      cur = { guard: /nonReentrant/.test(l), viewPure: /\b(view|pure)\b/.test(l), exposed: /\b(external|public)\b/.test(l), closed: l.includes('{') };
      let j = i;
      while (cur && !cur.closed && j < lines.length - 1) {
        j++;
        if (/nonReentrant/.test(lines[j])) cur.guard = true;
        if (/\b(view|pure)\b/.test(lines[j])) cur.viewPure = true;
        if (/\b(external|public)\b/.test(lines[j])) cur.exposed = true;
        if (lines[j].includes('{')) cur.closed = true;
      }
    }
    if (valueMove.test(l) && cur && cur.exposed && !cur.guard && !cur.viewPure) {
      out.push({ line: i + 1, snippet: l.trim().slice(0, 150) });
    }
  }
  return out;
}

module.exports = [
  // ---------- CRITICAL ----------
  {
    id: 'X402-BROADCAST-NO-AUTH', severity: 'critical', category: 'auth / fund movement', langs: ['js'],
    title: 'Server endpoint signs & broadcasts an on-chain transaction with no auth check',
    why: 'A request handler creates a wallet from a private key and broadcasts a transaction without any HMAC / signature / bearer check — anyone who can hit the endpoint can move funds.',
    fix: 'Gate the broadcast behind a verified HMAC/signature (timestamp + body hash), or remove the server-broadcast path in favor of a user-signed meta-transaction.',
    ref: 'AWM audit C1; OWASP A01',
    detect(ctx) {
      if (!isHandler(ctx) || isClientSide(ctx)) return [];
      const t = code(ctx);
      if (!/new\s+ethers\.Wallet\(/.test(t)) return [];
      if (!/\.sendTransaction\(|\.broadcastTransaction\(|\.writeContract\(/.test(t)) return []; // require a real broadcast, not address derivation
      if (/hmac|x-awm-signature|verifysignature|isvalidsignature|requireauth|authorize|bearer|timingsafeequal|x-admin-secret/i.test(t)) return [];
      return firstLine(ctx.lines, /\.sendTransaction\(|\.broadcastTransaction\(|\.writeContract\(/);
    }
  },
  {
    id: 'X402-HARDCODED-SECRET', severity: 'critical', category: 'secrets',
    title: 'Hardcoded private key / secret in source',
    why: 'A raw private key, mnemonic, or live API key is committed in source. Even a public test key (e.g. the Anvil default) normalizes a catastrophic pattern; a real one means immediate fund loss.',
    fix: 'Move to environment variables / a secret manager. Purge from git history (git filter-repo / BFG). Rotate anything real.',
    ref: 'AWM audit C6; CWE-798',
    detect(ctx) {
      const p = (ctx.rel || ctx.path).replace(/\\/g, '/');
      // skip test scaffolding — committed keys there are almost always dummies
      if (/\.(test|spec)\.[a-z]+$|(^|\/)(tests?|e2e|mocks?|__tests__|__fixtures__|fixtures)\//i.test(p)) return [];
      // obvious placeholder keys (zero, sequential, all-same-char) + well-known Anvil/Hardhat defaults
      const DUMMY = /^0+1?$|^(0123456789|1234567890){2,}|^(.)\1{30,}$|deadbeef/i;
      const ANVIL = /ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80|59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d|5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a/i;
      const out = [];
      for (let i = 0; i < ctx.lines.length; i++) {
        const l = ctx.lines[i];
        const m = l.match(/["'`]0x([0-9a-fA-F]{64})["'`]/);
        if (m) {
          const hex = m[1];
          if (/^0+$/.test(hex) || DUMMY.test(hex) || ANVIL.test(hex)) continue;
          // a 64-hex literal is only a *private key* if the context says so — otherwise
          // it's an event topic / keccak hash / merkle root / salt / selector (all public).
          const keyish = /(private[_ ]?key|privkey|secret|mnemonic|signer|deployer|\bpk\b|\bwallet\b|account|fromprivatekey|new\s+ethers\.wallet|privatekeytoaccount)/i.test(l);
          const hashish = /(event|topic|hash|root|selector|domain|salt|\bsig\b|signature|digest|merkle|commit|typehash|abi|interface)/i.test(l);
          if (!keyish || hashish) continue;
          out.push({ line: i + 1, snippet: l.trim().slice(0, 150) });
          continue;
        }
        if (/sk_live_[0-9a-zA-Z]{10,}|BEGIN [A-Z ]*PRIVATE KEY/.test(l)) { out.push({ line: i + 1, snippet: l.trim().slice(0, 150) }); continue; }
        // mnemonic: only flag real-looking phrases (12+ words, not placeholders)
        const mm = l.match(/mnemonic\s*[:=]\s*["'`]([^"'`]+)["'`]/i);
        if (mm && mm[1].trim().split(/\s+/).length >= 12 && !/word1|word2|\.\.\.|…|xxx|your[_ ]|example|test test|abandon abandon/i.test(mm[1])) out.push({ line: i + 1, snippet: l.trim().slice(0, 150) });
      }
      return out;
    }
  },

  // ---------- HIGH ----------
  {
    id: 'X402-REPLAY-NO-NONCE', severity: 'high', category: 'replay (Five Attacks #I)', langs: ['js'],
    title: 'Settlement handler appears to lack replay protection (nonce/idempotency)',
    why: 'x402 has no application-layer nonce: a signed payment token, once leaked/intercepted, can be resubmitted to debit again. Settlement/consume handlers must dedupe.',
    fix: 'Persist a used-token/nonce/requestId set (Redis/KV) and reject repeats; bind each token to a single settlement.',
    ref: 'Five Attacks on x402 #I (arXiv:2605.11781)',
    detect(ctx) {
      if (!isHandler(ctx) || isClientSide(ctx)) return [];
      const t = code(ctx);
      if (!/x402|settle|consume|receipt|redeem|release|payout/i.test(rel(ctx) + t)) return [];
      if (!/safeTransfer|sendTransaction|writeContract|\bmarkPaid\b|\bpayout\b|release\s*\(/i.test(t)) return [];
      if (/nonce|idempoten|already(Used|Processed|Settled)|usedDigest|jti|dedup|seen[A-Z]|replay/i.test(t)) return [];
      return firstLine(ctx.lines, /safeTransfer|sendTransaction|writeContract|\bmarkPaid\b|\bpayout\b|release\s*\(/i);
    }
  },
  {
    id: 'X402-IDEMPOTENCY', severity: 'high', category: 'idempotency (Five Attacks #II)', langs: ['js'],
    title: 'Payment callback/webhook handler may lack exactly-once protection',
    why: 'A retryable POST/callback between a bearer payment header and async on-chain settlement can double-process (paid-twice / double-deliver).',
    fix: 'Require an idempotency key and store processed keys; make settlement exactly-once.',
    ref: 'Five Attacks on x402 #II',
    detect(ctx) {
      if (!isHandler(ctx) || isClientSide(ctx)) return [];
      const t = code(ctx);
      if (!/webhook|callback/i.test(rel(ctx) + t)) return [];
      if (!/(req|request)\.(body|query)/.test(t)) return [];
      if (!/safeTransfer|sendTransaction|writeContract|\bmarkPaid\b|\bfulfil|\bdeliver\b|\bpayout\b/i.test(t)) return [];
      if (/idempoten|exactly.?once|already(Processed|Delivered|Settled)|processedSet|dedup|usedDigest|nonce/i.test(t)) return [];
      return firstLine(ctx.lines, /safeTransfer|sendTransaction|writeContract|\bmarkPaid\b|\bfulfil|\bdeliver\b|\bpayout\b/i);
    }
  },
  {
    id: 'X402-FAILOPEN-SECRET', severity: 'high', category: 'auth (fail-open)', langs: ['js'],
    title: 'Auth check is skipped when its secret env var is unset (fails open)',
    why: 'An "if (process.env.SECRET && ...)" guard means that if the env var is missing, the check is bypassed entirely — the endpoint becomes unauthenticated.',
    fix: 'Fail closed: if the secret is not configured, reject (401/503) instead of allowing the request.',
    ref: 'AWM audit (cron) H4',
    detect(ctx) {
      if (isClientSide(ctx)) return [];
      return linesMatching(ctx.lines, /if\s*\(\s*process\.env\.[A-Z0-9_]+\s*&&/);
    }
  },
  {
    id: 'X402-SSRF-WEBHOOK', severity: 'high', category: 'SSRF', langs: ['js'],
    title: 'Outbound request to a dynamic (user-supplied) URL with no SSRF guard',
    why: 'Delivering webhooks (or fetching) to attacker-controlled URLs with no allowlist lets an attacker hit internal services / cloud metadata (169.254.169.254).',
    fix: 'Validate destination URLs against an allowlist; block private/link-local ranges; re-check the resolved IP at connection time.',
    ref: 'AWM audit H4; OWASP SSRF',
    detect(ctx) {
      if (isClientSide(ctx)) return [];
      const t = code(ctx);
      if (!/webhook|subscriber|callback/i.test(rel(ctx) + t)) return [];
      // dynamic URL: fetch(variable...) / axios.post(variable...) — not a hardcoded literal endpoint
      if (!/\bfetch\(\s*[a-zA-Z_$]/.test(t) && !/axios\.(post|get|request)\(\s*[a-zA-Z_$]/.test(t) && !/http\.request\(\s*[a-zA-Z_$]/.test(t)) return [];
      if (/allowlist|allowList|isPrivate|blocklist|169\.254|127\.0|metadata|hostname/i.test(t)) return [];
      return firstLine(ctx.lines, /\bfetch\(\s*[a-zA-Z_$]|axios\.(post|get|request)\(\s*[a-zA-Z_$]|http\.request\(\s*[a-zA-Z_$]/);
    }
  },
  {
    id: 'SOL-REENTRANCY', severity: 'high', category: 'reentrancy', langs: ['sol'],
    title: 'Exposed value-moving function without a reentrancy guard',
    why: 'An external/public function that transfers tokens (or makes a value call) without nonReentrant + CEI ordering can be re-entered, enabling double-spend.',
    fix: 'Add OpenZeppelin nonReentrant; set state before external calls (checks-effects-interactions).',
    ref: 'AWM audit C2; SWC-107',
    detect: solUnguardedValueMove
  },
  {
    id: 'SOL-TX-ORIGIN-OWNER', severity: 'high', category: 'access control', langs: ['sol'],
    title: 'tx.origin used (often as deploy owner) — hot-EOA / phishing risk',
    why: 'Setting owner/admin to tx.origin (a hot EOA) means a single key controls the contract; tx.origin is also phishing-prone. Owner should be a Safe + Timelock.',
    fix: 'Pass an explicit initialOwner = multisig/timelock; never authorize on tx.origin.',
    ref: 'AWM audit H3; SWC-115',
    detect(ctx) { return linesMatching(ctx.lines, /tx\.origin/); }
  },

  // ---------- MEDIUM ----------
  {
    id: 'SOL-RAW-ERC20', severity: 'medium', category: 'ERC20 safety', langs: ['sol'],
    title: 'Raw ERC20 transfer/transferFrom (not SafeERC20)',
    why: 'Some tokens (USDT-style) do not return a bool; a raw .transfer can silently fail. Use SafeERC20.',
    fix: 'Use OpenZeppelin SafeERC20 (safeTransfer / safeTransferFrom).',
    ref: 'SWC-104',
    detect(ctx) { if (!inContracts(ctx)) return []; return linesMatching(ctx.lines, /\.transfer(From)?\s*\(/); }
  },
  {
    id: 'SOL-UNLIMITED-APPROVAL', severity: 'medium', category: 'allowance (Five Attacks #III)', langs: ['sol', 'js'],
    title: 'Unlimited / max token approval',
    why: 'Granting type(uint256).max allowance means a bug or compromise can drain the full balance, not just the intended amount.',
    fix: 'Approve only the exact amount needed; reset to 0 after; consider permit-style scoped approvals.',
    ref: 'Five Attacks on x402 #III (allowance bypass)',
    detect(ctx) { return linesMatching(ctx.lines, /approve\(/, /max|MaxUint|ffffffffffffffff|2\*\*256|type\(uint256\)/i); }
  },
  {
    id: 'SOL-PRIVILEGED-NO-MODIFIER', severity: 'medium', category: 'access control', langs: ['sol'],
    title: 'Privileged setter without an access-control modifier',
    why: 'Functions like set*/withdraw*/rescue*/upgrade*/pause that lack onlyOwner/onlyRole may be callable by anyone.',
    fix: 'Add onlyOwner / onlyRole (or an explicit require(msg.sender == ...)).',
    ref: 'SWC-105',
    detect(ctx) {
      if (!inContracts(ctx)) return [];
      const out = [];
      const { lines } = ctx;
      for (let i = 0; i < lines.length; i++) {
        if (!/function\s+(set|withdraw|rescue|upgrade|pause|unpause|mint|setFee|setVerifier|setZKVerifier|migrate)\w*/i.test(lines[i])) continue;
        let sig = lines[i], j = i;
        while (!sig.includes('{') && j < lines.length - 1) { j++; sig += ' ' + lines[j]; }
        if (!/onlyOwner|onlyRole|require\(\s*msg\.sender|_checkOwner|hasRole/i.test(sig)) out.push({ line: i + 1, snippet: lines[i].trim().slice(0, 150) });
      }
      return out;
    }
  },
  {
    id: 'X402-WEAK-RANDOM', severity: 'medium', category: 'predictable identifiers', langs: ['js'],
    title: 'Math.random() used for an id / token / nonce',
    why: 'Math.random() is not a CSPRNG. Correlation IDs / tokens / nonces built from it are predictable and forgeable.',
    fix: 'Use crypto.randomUUID() or crypto.randomBytes(16).toString("hex").',
    ref: 'AWM audit L13; CWE-338',
    detect(ctx) { return linesMatching(ctx.lines, /Math\.random\(\)/, /id|token|nonce|secret|key|quote|request|session/i); }
  },
  {
    id: 'X402-STACKTRACE-LEAK', severity: 'medium', category: 'info disclosure', langs: ['js'],
    title: 'Stack trace / raw error returned in an HTTP response',
    why: 'Returning e.stack / raw e.message to clients leaks internal paths, dependencies, and code structure. (Server-side console logging is fine — this flags response bodies only.)',
    fix: 'Log full errors server-side; return an opaque error code to the client.',
    ref: 'AWM audit M1/M8; CWE-209',
    detect(ctx) {
      if (isClientSide(ctx)) return [];
      const out = [];
      const seen = new Set();
      for (let i = 0; i < ctx.lines.length; i++) {
        const l = ctx.lines[i];
        const inResponse = /res\.(status\([^)]*\)\.)?(json|send|end)\(|return\s+Response|return\s+res|res\.write\(|json\(\{/.test(l);
        const leaks = /\.stack\b|\.message\b/.test(l) || /(stack|message|error)\s*:\s*[\w.]*(err|error|e)\.(stack|message)/.test(l);
        if (inResponse && leaks && !seen.has(i)) { seen.add(i); out.push({ line: i + 1, snippet: l.trim().slice(0, 150) }); }
      }
      return out;
    }
  },

  // ---------- LOW ----------
  {
    id: 'X402-CORS-WILDCARD', severity: 'low', category: 'CORS', langs: ['js'],
    title: 'Wildcard CORS (Access-Control-Allow-Origin: *)',
    why: 'Wildcard CORS on endpoints that expose tools/data lets any web page invoke them cross-origin.',
    fix: 'Restrict to known origins; keep wildcard only for intentionally-public, read-only discovery endpoints.',
    ref: 'OWASP',
    detect(ctx) { return linesMatching(ctx.lines, /Access-Control-Allow-Origin/, /\*/); }
  },
  {
    id: 'X402-INMEM-RATELIMIT', severity: 'low', category: 'rate limiting', langs: ['js'],
    title: 'In-memory rate limiter (ineffective on serverless)',
    why: 'A per-process Map rate limiter resets on every cold start and is not shared across serverless instances — so it barely limits anything.',
    fix: 'Use a shared store (Redis/Upstash) or edge/WAF rate limiting.',
    ref: 'AWM audit M11',
    detect(ctx) {
      if (!/rate|bucket|limit|throttle/i.test(ctx.text)) return [];
      return linesMatching(ctx.lines, /new\s+Map\(\)/, /rate|bucket|limit|throttle/i);
    }
  }
];
