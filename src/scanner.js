'use strict';
const fs = require('fs');
const path = require('path');
const rules = require('./rules');

const SKIP = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out',
  'artifacts', 'cache', 'lib', '.vercel', 'forge-cache', 'broadcast', 'typechain-types'
]);
const EXT = { '.sol': 'sol', '.js': 'js', '.jsx': 'js', '.ts': 'js', '.tsx': 'js', '.mjs': 'js', '.cjs': 'js', '.py': 'py' };
const SEVERITY_WEIGHT = { critical: 35, high: 12, medium: 4, low: 1 };
const MAX_BYTES = 800000;

function walk(target, acc) {
  let st;
  try { st = fs.statSync(target); } catch { return acc; }
  if (st.isFile()) { if (EXT[path.extname(target)]) acc.push(target); return acc; }
  let entries = [];
  try { entries = fs.readdirSync(target); } catch { return acc; }
  for (const name of entries) {
    if (SKIP.has(name)) continue;
    const p = path.join(target, name);
    let s;
    try { s = fs.statSync(p); } catch { continue; }
    if (s.isDirectory()) walk(p, acc);
    else if (EXT[path.extname(name)]) acc.push(p);
  }
  return acc;
}

function scan(target) {
  const root = path.resolve(target);
  const files = walk(root, []);
  const findings = [];
  for (const file of files) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (text.length > MAX_BYTES) continue;
    const lines = text.split(/\r?\n/);
    const lang = EXT[path.extname(file)];
    const relPath = path.relative(root, file) || path.basename(file);
    // comment-stripped copy: mitigation/keyword checks run against this so a
    // comment ("// we verify the HMAC here") can't hide a real vulnerability.
    const code = text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
    const ctx = { text, code, lines, path: file, rel: relPath, lang };
    for (const rule of rules) {
      if (rule.langs && !rule.langs.includes(lang)) continue;
      let hits = [];
      try { hits = rule.detect(ctx) || []; } catch { hits = []; }
      for (const h of hits) {
        findings.push({
          ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category,
          why: rule.why, fix: rule.fix, ref: rule.ref || '',
          file: path.relative(root, file) || path.basename(file), line: h.line, snippet: h.snippet || ''
        });
      }
    }
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let penalty = 0;
  for (const f of findings) { counts[f.severity]++; penalty += SEVERITY_WEIGHT[f.severity] || 0; }
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const letter = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F';
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { findings, score, letter, counts, filesScanned: files.length, ruleCount: rules.length };
}

module.exports = { scan };
