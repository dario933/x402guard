'use strict';
// Zero-dependency test runner. Scans __fixtures__ and asserts the right rules fire
// on vulnerable code and stay silent on the hardened equivalent.
const path = require('path');
const { scan } = require('../src/scanner');

const root = path.join(__dirname, '..', '__fixtures__');
const r = scan(root);
const ids = new Set(r.findings.map(f => f.ruleId));

const expected = [
  'X402-BROADCAST-NO-AUTH',
  'X402-WEAK-RANDOM',
  'X402-STACKTRACE-LEAK',
  'SOL-REENTRANCY',
  'SOL-TX-ORIGIN-OWNER',
  'SOL-PRIVILEGED-NO-MODIFIER'
];

let failed = 0;
for (const id of expected) {
  if (ids.has(id)) console.log('  ok    detects ' + id);
  else { console.error('  FAIL  expected rule did not fire: ' + id); failed++; }
}

const safeHits = r.findings.filter(f => /safe-handler/.test(f.file));
if (safeHits.length === 0) console.log('  ok    hardened handler is clean (no false positives)');
else { console.error('  FAIL  safe-handler.js should be clean, got: ' + safeHits.map(f => f.ruleId).join(', ')); failed++; }

// Drift guard: the hosted grader vendors src/rules.js into api/_rules.js — they must match.
const fs = require('fs');
const srcRules = fs.readFileSync(path.join(__dirname, '..', 'src', 'rules.js'), 'utf8');
const vendored = fs.readFileSync(path.join(__dirname, '..', 'api', '_rules.js'), 'utf8').replace(/^[^\n]*\n/, '');
if (srcRules === vendored) console.log('  ok    vendored api/_rules.js in sync with src/rules.js');
else { console.error('  FAIL  api/_rules.js is OUT OF SYNC with src/rules.js — re-vendor it'); failed++; }

console.log('');
if (failed) { console.error(failed + ' test(s) failed'); process.exit(1); }
console.log('All tests passed (' + r.findings.length + ' findings across fixtures).');
process.exit(0);
