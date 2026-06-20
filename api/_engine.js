'use strict';
// In-memory scan engine for the hosted grader. Reuses the SAME ruleset as the
// CLI (../src/rules.js) so the web grade and the CLI grade never diverge.
// require the vendored copy so src/ can be excluded from the public deployment
const rules = require('./_rules.js');

const EXT = { '.sol': 'sol', '.js': 'js', '.jsx': 'js', '.ts': 'js', '.tsx': 'js', '.mjs': 'js', '.cjs': 'js', '.py': 'py' };
const SEVERITY_WEIGHT = { critical: 35, high: 12, medium: 4, low: 1 };
const MAX_FILE_BYTES = 400000;

const extOf = p => { const m = /\.[a-z]+$/i.exec(p || ''); return m ? m[0].toLowerCase() : ''; };

function buildCtx(p, text) {
  const lang = EXT[extOf(p)] || 'js';
  const lines = text.split(/\r?\n/);
  const code = text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
  return { text, code, lines, path: p, rel: p, lang };
}

function scanFiles(files) {
  const findings = [];
  for (const f of files) {
    if (!f || typeof f.text !== 'string' || f.text.length > MAX_FILE_BYTES) continue;
    const ctx = buildCtx(f.path || 'snippet.js', f.text);
    for (const rule of rules) {
      if (rule.langs && !rule.langs.includes(ctx.lang)) continue;
      let hits = [];
      try { hits = rule.detect(ctx) || []; } catch { hits = []; }
      for (const h of hits) {
        findings.push({
          ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category,
          why: rule.why, fix: rule.fix, ref: rule.ref || '', file: ctx.rel, line: h.line, snippet: h.snippet || ''
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
  return { score, letter, counts, findings, filesScanned: files.length, ruleCount: rules.length };
}

module.exports = { scanFiles, EXT, extOf };
