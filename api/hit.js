'use strict';
// Privacy-friendly pageview beacon. No cookies, no IP, no PII — just aggregate counters
// in Upstash: total views, by page, by day (UTC), and by referrer host. Fire-and-forget.
const done = (res, code = 204) => { res.statusCode = code; res.setHeader('Cache-Control', 'no-store'); res.end(); };
const clean = (s, n) => String(s || '').replace(/[^a-zA-Z0-9/_.:-]/g, '').slice(0, n || 60);

async function readBody(req) {
  if (req.body) { try { return typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch { return {}; } }
  return await new Promise(resolve => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 2000) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return done(res, 405);
  const url = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return done(res, 204);
  let b = {}; try { b = await readBody(req); } catch { }
  const p = clean(b.p, 60) || '/';
  const r = clean(b.r, 60) || 'direct';
  const day = new Date().toISOString().slice(0, 10);
  const base = url.trim().replace(/\/+$/, '');
  try {
    await fetch(`${base}/pipeline`, {
      method: 'POST', headers: { Authorization: `Bearer ${token.trim()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([
        ['INCR', 'x402guard:stats:total'],
        ['HINCRBY', 'x402guard:stats:pages', p, 1],
        ['HINCRBY', 'x402guard:stats:days', day, 1],
        ['HINCRBY', 'x402guard:stats:refs', r, 1]
      ]),
      signal: AbortSignal.timeout(2500)
    });
  } catch { /* never block the page on analytics */ }
  return done(res, 204);
};
