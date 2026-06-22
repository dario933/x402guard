'use strict';
// Private admin view of captured leads. GET /api/leads?key=<LEADS_KEY> (or Authorization: Bearer <LEADS_KEY>).
// Renders an HTML table (newest first); add &json=1 for raw JSON. Env: LEADS_KEY + Upstash creds.
const send = (res, status, body, type) => {
  res.statusCode = status;
  res.setHeader('Content-Type', type || 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

module.exports = async (req, res) => {
  const key = process.env.LEADS_KEY;
  const u = new URL(req.url, 'http://x');
  const given = u.searchParams.get('key') || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!key || given !== key) return send(res, 401, { error: 'unauthorized' });

  const urlRaw = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!urlRaw || !token) return send(res, 503, { error: 'storage_not_configured' });
  const base = urlRaw.trim().replace(/\/+$/, '');

  let leads = [];
  try {
    const r = await fetch(`${base}/lrange/x402guard:leads/0/-1`, { headers: { Authorization: `Bearer ${token.trim()}` }, signal: AbortSignal.timeout(4000) });
    const body = await r.json();
    leads = (body.result || []).map(s => { try { return JSON.parse(s); } catch { return { raw: s }; } });
  } catch (e) { return send(res, 502, { error: 'fetch_failed' }); }

  if (u.searchParams.get('json') === '1') return send(res, 200, { count: leads.length, leads });

  const rows = leads.map(l => `<tr>
    <td>${esc((l.at || '').replace('T', ' ').slice(0, 16))}</td>
    <td><a href="mailto:${esc(l.email)}">${esc(l.email)}</a></td>
    <td><b>${esc(l.grade)}</b></td>
    <td>${l.repo ? `<a href="${esc(l.repo)}" target="_blank" rel="noopener">${esc(l.repo)}</a>` : ''}</td>
    <td>${esc(l.msg)}</td>
    <td>${esc(l.ip)}</td></tr>`).join('');
  const html = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>x402guard leads (${leads.length})</title>
<style>body{background:#0b0a14;color:#eceaf6;font:14px -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:28px}
h1{font-size:18px;margin:0 0 14px}h1 b{color:#b08bff}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #2a2350;vertical-align:top}
th{color:#7d76a8;font-size:12px;text-transform:uppercase;letter-spacing:.4px}a{color:#b08bff}
td:nth-child(5){max-width:380px;color:#a79fce}.empty{color:#7d76a8;padding:30px 0}</style>
<h1>x402<b>guard</b> leads · <b>${leads.length}</b></h1>
${leads.length ? `<table><tr><th>When (UTC)</th><th>Email</th><th>Grade</th><th>Repo</th><th>Message</th><th>IP</th></tr>${rows}</table>`
  : `<p class="empty">No leads yet.</p>`}`;
  return send(res, 200, html, 'text/html; charset=utf-8');
};
