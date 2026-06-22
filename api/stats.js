'use strict';
// Private analytics dashboard. GET /api/stats?key=<LEADS_KEY> (HTML; &json=1 for JSON).
// Reads the aggregate counters written by api/hit.js. No PII.
const { timingSafeEqual } = require('crypto');
const safeEqual = (a, b) => { const ab = Buffer.from(String(a)), bb = Buffer.from(String(b)); return ab.length === bb.length && timingSafeEqual(ab, bb); };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const send = (res, status, body, type) => { res.statusCode = status; res.setHeader('Content-Type', type || 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Robots-Tag', 'noindex'); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
const pairs = arr => { const o = {}; for (let i = 0; i < (arr || []).length; i += 2) o[arr[i]] = Number(arr[i + 1]) || 0; return o; };

module.exports = async (req, res) => {
  const key = process.env.LEADS_KEY, u = new URL(req.url, 'http://x');
  const given = u.searchParams.get('key') || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!key || !safeEqual(given, key)) return send(res, 401, { error: 'unauthorized' });
  const url = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return send(res, 503, { error: 'storage_not_configured' });
  const base = url.trim().replace(/\/+$/, ''), h = { Authorization: `Bearer ${token.trim()}`, 'Content-Type': 'application/json' };

  let total = 0, pages = {}, days = {}, refs = {};
  try {
    const r = await fetch(`${base}/pipeline`, { method: 'POST', headers: h, body: JSON.stringify([
      ['GET', 'x402guard:stats:total'], ['HGETALL', 'x402guard:stats:pages'], ['HGETALL', 'x402guard:stats:days'], ['HGETALL', 'x402guard:stats:refs']
    ]), signal: AbortSignal.timeout(4000) });
    const j = await r.json();
    total = Number(j[0] && j[0].result) || 0; pages = pairs(j[1] && j[1].result); days = pairs(j[2] && j[2].result); refs = pairs(j[3] && j[3].result);
  } catch { return send(res, 502, { error: 'fetch_failed' }); }

  if (u.searchParams.get('json') === '1') return send(res, 200, { total, pages, days, refs });

  const tbl = (obj, k1, k2, sortByKey) => {
    const rows = Object.entries(obj).sort(sortByKey ? (a, b) => a[0].localeCompare(b[0]) : (a, b) => b[1] - a[1]);
    if (!rows.length) return '<p class="empty">—</p>';
    return `<table><tr><th>${k1}</th><th>${k2}</th></tr>${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('')}</table>`;
  };
  const html = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>x402guard analytics</title>
<style>body{background:#0b0a14;color:#eceaf6;font:14px -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:28px;max-width:760px}
h1{font-size:18px;margin:0 0 4px}h1 b{color:#b08bff}.sub{color:#7d76a8;font-size:12px;margin-bottom:20px}
.big{font-size:44px;font-weight:800;letter-spacing:-1px;margin:6px 0 24px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#7d76a8;margin:26px 0 8px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #2a2350}
th{color:#7d76a8;font-size:11px;text-transform:uppercase}td:last-child{text-align:right;font-weight:700;color:#b08bff;width:90px}
.empty{color:#7d76a8}</style>
<h1>x402<b>guard</b> analytics</h1><div class="sub">privacy-friendly · no cookies · no IP · UTC days</div>
<div class="big">${total} <span style="font-size:15px;color:#7d76a8;font-weight:400">total pageviews</span></div>
<h2>By day</h2>${tbl(days, 'Day (UTC)', 'Views', true)}
<h2>By page</h2>${tbl(pages, 'Path', 'Views')}
<h2>Top referrers</h2>${tbl(refs, 'Source', 'Views')}`;
  return send(res, 200, html, 'text/html; charset=utf-8');
};
