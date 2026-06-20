'use strict';

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', orange: '\x1b[33m', yellow: '\x1b[93m', gray: '\x1b[90m',
  green: '\x1b[32m', cyan: '\x1b[36m'
};
const SEV_COLOR = { critical: C.red, high: C.orange, medium: C.yellow, low: C.gray };
const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ' };
const useColor = () => process.stdout.isTTY;
const paint = (s, c) => (useColor() ? c + s + C.reset : s);

function gradeLine(r) {
  const c = r.letter === 'A' ? C.green : r.letter === 'B' ? C.cyan : r.letter === 'F' ? C.red : C.orange;
  return paint(`  GRADE ${r.letter}  (${r.score}/100)`, C.bold + c);
}

function renderText(r, target) {
  const out = [];
  out.push('');
  out.push(paint('  x402guard', C.bold + C.cyan) + paint('  · security scan for x402 / agent-payment integrations', C.dim));
  out.push(paint(`  target: ${target}   files: ${r.filesScanned}   rules: ${r.ruleCount}`, C.dim));
  out.push('');
  out.push(gradeLine(r));
  out.push(paint(
    `  critical ${r.counts.critical}   high ${r.counts.high}   medium ${r.counts.medium}   low ${r.counts.low}`,
    C.dim));
  out.push('');
  if (!r.findings.length) {
    out.push(paint('  No findings from the current ruleset. (Not a substitute for a professional audit.)', C.green));
    out.push('');
    return out.join('\n');
  }
  let lastSev = '';
  for (const f of r.findings) {
    if (f.severity !== lastSev) {
      out.push('');
      out.push(paint(`  ── ${f.severity.toUpperCase()} ${'─'.repeat(Math.max(0, 56 - f.severity.length))}`, SEV_COLOR[f.severity] + C.bold));
      lastSev = f.severity;
    }
    out.push(`  ${paint('[' + SEV_LABEL[f.severity] + ']', SEV_COLOR[f.severity])} ${paint(f.ruleId, C.bold)}  ${paint(f.file + ':' + f.line, C.cyan)}`);
    out.push(`        ${f.title}`);
    if (f.snippet) out.push(paint(`        > ${f.snippet}`, C.dim));
    out.push(paint(`        why: ${f.why}`, C.gray));
    out.push(paint(`        fix: ${f.fix}`, C.gray));
    if (f.ref) out.push(paint(`        ref: ${f.ref}`, C.gray));
    out.push('');
  }
  out.push(paint('  Heuristic SAST — verify each finding; complements, does not replace, a professional audit.', C.dim));
  out.push('');
  return out.join('\n');
}

function renderJson(r) { return JSON.stringify(r, null, 2); }

function esc(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }

function renderHtml(r, target) {
  const sevc = { critical: '#b3261e', high: '#e0701d', medium: '#d9a72a', low: '#6b7688' };
  const gradeColor = r.letter === 'A' ? '#2e9e5b' : r.letter === 'B' ? '#2f80b3' : r.letter === 'F' ? '#b3261e' : '#e0701d';
  const rows = r.findings.map(f => `
    <tr>
      <td><span class="badge" style="background:${sevc[f.severity]}">${f.severity.toUpperCase()}</span></td>
      <td><code>${esc(f.ruleId)}</code><div class="ttl">${esc(f.title)}</div></td>
      <td><code>${esc(f.file)}:${f.line}</code>${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ''}</td>
      <td>${esc(f.fix)}${f.ref ? `<div class="ref">${esc(f.ref)}</div>` : ''}</td>
    </tr>`).join('');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>x402guard report</title><style>
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#1c2433;margin:0;font-size:13px;line-height:1.5}
.head{background:linear-gradient(135deg,#0f1c33,#27123f);color:#fff;padding:30px 34px}
.logo{font-size:22px;font-weight:800;letter-spacing:-.5px}.logo span{color:#7c5cff}
.sub{color:#b9b1d6;font-size:12.5px;margin-top:3px}
.grade{display:inline-flex;align-items:center;gap:14px;margin-top:18px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);border-radius:10px;padding:12px 20px}
.gletter{font-size:40px;font-weight:800;color:${gradeColor};line-height:1}
.gnum{font-size:12px;color:#b9b1d6}
.counts{margin-top:14px;font-size:12px;color:#cdc6e6}
.counts b{color:#fff}
.wrap{padding:22px 34px 40px}
table{width:100%;border-collapse:collapse;margin-top:6px}
th{background:#0f1c33;color:#fff;text-align:left;padding:7px 9px;font-size:11px}
td{border-bottom:1px solid #e6eaf1;padding:8px 9px;vertical-align:top}
tr:nth-child(even) td{background:#f7f9fc}
.badge{display:inline-block;color:#fff;font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;white-space:nowrap}
.ttl{margin-top:3px;font-size:12px;color:#33405a}
.ref{color:#7a8194;font-size:10.5px;margin-top:4px}
code{font-family:Consolas,monospace;font-size:11px;background:#eef1f6;padding:1px 4px;border-radius:3px}
pre{font-family:Consolas,monospace;font-size:10.5px;background:#f3f5f9;border:1px solid #e6eaf1;border-radius:4px;padding:6px 8px;margin:5px 0 0;white-space:pre-wrap;word-break:break-word}
.note{margin-top:18px;color:#5b6678;font-size:11px;border-top:1px solid #e6eaf1;padding-top:10px}
</style></head><body>
<div class="head">
  <div class="logo">x402<span>guard</span></div>
  <div class="sub">Security scan for x402 / agent-payment integrations — the web↔chain glue general scanners miss</div>
  <div class="grade"><div class="gletter">${r.letter}</div><div><div style="font-weight:700;color:#fff">${r.score}/100</div><div class="gnum">security grade</div></div></div>
  <div class="counts">target <b>${esc(target)}</b> &nbsp;·&nbsp; ${r.filesScanned} files &nbsp;·&nbsp; ${r.ruleCount} rules &nbsp;·&nbsp; <b style="color:#ff8a7a">${r.counts.critical}</b> critical · <b style="color:#ffb27a">${r.counts.high}</b> high · ${r.counts.medium} medium · ${r.counts.low} low</div>
</div>
<div class="wrap">
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Fix</th></tr></thead><tbody>
${rows || '<tr><td colspan="4">No findings from the current ruleset.</td></tr>'}
</tbody></table>
<div class="note">Generated by x402guard v0.1 — heuristic static analysis. Verify each finding manually; this complements but does not replace a professional smart-contract / ZK audit.</div>
</div></body></html>`;
}

module.exports = { renderText, renderJson, renderHtml };
