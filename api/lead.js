'use strict';
// Lead capture for the grader's "Book a security review" form.
//  - Validates email; honeypot drops bots silently.
//  - Stores the lead in Upstash Redis (durable) and emails it via Resend (notification).
//  - Both are best-effort/fail-soft: a lead is never lost just because email isn't configured.
// Env: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN (already set for rate limiting),
//      RESEND_API_KEY, LEAD_TO (dario@dmeomaha.com), LEAD_FROM ("x402guard <onboarding@resend.dev>").
const MAX_BODY = 100000;
const RL_WINDOW = 600;   // seconds
const RL_LIMIT = 6;      // lead submissions per window per IP

const send = (res, status, obj) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { throw new Error('badjson'); } }
    return req.body;
  }
  return await new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { req.destroy(); reject(new Error('toobig')); return; } chunks.push(c); });
    req.on('end', () => { try { const s = Buffer.concat(chunks).toString('utf8'); resolve(s ? JSON.parse(s) : {}); } catch { reject(new Error('badjson')); } });
    req.on('error', () => reject(new Error('stream')));
  });
}

function clientIp(req) {
  // On Vercel, x-real-ip is the true client IP and cannot be spoofed by the client.
  // Fall back to the LAST x-forwarded-for entry (the one the platform appends), never the first.
  const xff = (req.headers['x-forwarded-for'] || '').toString();
  return (req.headers['x-real-ip'] || xff.split(',').pop() || 'unknown').toString().trim();
}

async function rateLimited(req) {
  const urlRaw = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!urlRaw || !token) return false; // not configured -> don't block
  const url = urlRaw.trim().replace(/\/+$/, '');
  const key = `x402guard:rl-lead:${clientIp(req)}`;
  const h = { Authorization: `Bearer ${token.trim()}` };
  try {
    // Atomic INCR + EXPIRE(NX) in one pipeline — avoids the race where a separate
    // EXPIRE can fail and leave the key with no TTL (which would permanently block an IP).
    const r = await fetch(`${url}/pipeline`, {
      method: 'POST', headers: { ...h, 'Content-Type': 'application/json' },
      body: JSON.stringify([['INCR', key], ['EXPIRE', key, RL_WINDOW, 'NX']]),
      signal: AbortSignal.timeout(3000)
    });
    const body = await r.json().catch(() => []);
    const n = Array.isArray(body) && body[0] && typeof body[0].result === 'number' ? body[0].result : 0;
    return n > RL_LIMIT;
  } catch { return false; } // fail open
}

async function storeLead(lead) {
  const urlRaw = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!urlRaw || !token) return false;
  const url = urlRaw.trim().replace(/\/+$/, '');
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token.trim()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['LPUSH', 'x402guard:leads', JSON.stringify(lead)]),
      signal: AbortSignal.timeout(3000)
    });
    return r.ok;
  } catch (e) { console.error('lead: store error', e && e.message); return false; }
}

async function emailLead(lead) {
  const key = process.env.RESEND_API_KEY;
  const to = process.env.LEAD_TO || 'dario@dmeomaha.com';
  const from = process.env.LEAD_FROM || 'x402guard <onboarding@resend.dev>';
  if (!key) return false;
  const text = `New x402guard security-review request\n\n` +
    `Email:  ${lead.email}\n` +
    `Repo:   ${lead.repo || '(none)'}\n` +
    `Grade:  ${lead.grade || '(n/a)'}\n` +
    `IP:     ${lead.ip}\n` +
    `Time:   ${lead.at}\n\n` +
    `Message:\n${lead.msg || '(none)'}\n`;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key.trim()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [to], reply_to: lead.email, subject: `x402guard lead: ${lead.email}${lead.grade ? ` (grade ${lead.grade})` : ''}`, text }),
      signal: AbortSignal.timeout(6000)
    });
    if (!r.ok) console.error('lead: resend', r.status, (await r.text().catch(() => '')).slice(0, 160));
    return r.ok;
  } catch (e) { console.error('lead: email error', e && e.message); return false; }
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

module.exports = async (req, res) => {
  if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
  if (await rateLimited(req)) return send(res, 429, { error: 'Too many requests — try again shortly or email dario@dmeomaha.com.' });

  let body;
  try { body = await readBody(req); } catch { return send(res, 400, { error: 'Invalid request.' }); }

  // Honeypot: real users never fill this hidden field. Pretend success, drop silently.
  if ((body.company || '').toString().trim()) return send(res, 200, { ok: true });

  const email = (body.email || '').toString().trim().slice(0, 200);
  if (!EMAIL_RE.test(email)) return send(res, 400, { error: 'Please enter a valid email.' });

  const repoRaw = (body.repo || '').toString().trim().slice(0, 300);
  const lead = {
    email,
    repo: /^https?:\/\//i.test(repoRaw) ? repoRaw : '', // only store real http(s) URLs (blocks javascript: etc.)
    msg: (body.msg || '').toString().trim().slice(0, 4000),
    grade: (body.grade || '').toString().trim().slice(0, 4),
    ip: clientIp(req),
    at: new Date().toISOString(),
    ua: (req.headers['user-agent'] || '').toString().slice(0, 200)
  };

  const stored = await storeLead(lead);
  const emailed = await emailLead(lead);
  if (!stored && !emailed) return send(res, 502, { error: 'Could not record your request — please email dario@dmeomaha.com directly.' });
  return send(res, 200, { ok: true });
};
