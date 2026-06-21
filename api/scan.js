'use strict';
// Hosted grader API. Two modes:
//   { code, filename }  -> scan a pasted snippet
//   { repo }            -> fetch a PUBLIC GitHub repo's source and scan it
// Security notes (we eat our own dog food):
//  - repo input is strictly parsed to owner/name; we only ever fetch
//    api.github.com / raw.githubusercontent.com — never an arbitrary URL (no SSRF).
//  - body size capped; errors are opaque (no stack traces leaked to clients).
const { scanFiles, EXT, extOf } = require('./_engine.js');

const SKIP_DIR = /(^|\/)(node_modules|\.git|dist|build|coverage|\.next|out|artifacts|cache|lib|tests?|mocks?|examples?|broadcast)\//;
const MAX_REPO_FILES = 30;
const MAX_PASTE = 200000;
const MAX_BODY = 1500000;

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

function parseRepo(url) {
  const m = /^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec((url || '').trim());
  if (!m) return null;
  if ([m[1], m[2]].some(s => s === '.' || s === '..')) return null; // no path traversal on api.github.com
  return { owner: m[1], repo: m[2] };
}

async function gh(path) {
  const r = await fetch('https://api.github.com' + path, { headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'x402guard-grader' }, signal: AbortSignal.timeout(8000) });
  if (r.status === 403) throw new Error('ratelimit');
  if (!r.ok) throw new Error('gh-' + r.status);
  return r.json();
}

async function fetchRepoFiles({ owner, repo }) {
  const meta = await gh(`/repos/${owner}/${repo}`);
  const branch = meta.default_branch || 'main';
  const tree = await gh(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);
  const all = (tree.tree || []).filter(n => n.type === 'blob' && EXT[extOf(n.path)] && !SKIP_DIR.test('/' + n.path) && (n.size || 0) < 300000);
  const wanted = all.slice(0, MAX_REPO_FILES);
  const settled = await Promise.allSettled(wanted.map(async n => {
    const raw = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${n.path}`, { headers: { 'User-Agent': 'x402guard-grader' }, signal: AbortSignal.timeout(8000) });
    return raw.ok ? { path: n.path, text: await raw.text() } : null;
  }));
  const files = settled.filter(s => s.status === 'fulfilled' && s.value).map(s => s.value);
  return { files, branch, truncated: all.length > MAX_REPO_FILES, totalCandidates: all.length };
}

// Rate limiting via Upstash Redis REST (no npm dependency). No-op until configured
// (set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN in the Vercel project env).
// Fail-open: any limiter error never blocks a legitimate scan.
const RL_WINDOW = 600;   // seconds
const RL_LIMIT = 30;     // requests per window per IP
async function rateState(req) {
  const urlRaw = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!urlRaw || !token) return { configured: false };
  const url = urlRaw.trim().replace(/\/+$/, '');
  const ip = (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown').toString().split(',')[0].trim();
  const key = `x402guard:rl:${ip}`;
  const h = { Authorization: `Bearer ${token.trim()}` };
  try {
    const r = await fetch(`${url}/incr/${encodeURIComponent(key)}`, { headers: h, signal: AbortSignal.timeout(3000) });
    const body = await r.json().catch(() => ({}));
    if (!r.ok || typeof body.result !== 'number') { console.error('rl: bad upstash response', r.status, JSON.stringify(body).slice(0, 120)); return { configured: true, error: true }; }
    const n = body.result;
    if (n === 1) await fetch(`${url}/expire/${encodeURIComponent(key)}/${RL_WINDOW}`, { headers: h, signal: AbortSignal.timeout(3000) });
    return { configured: true, count: n, limited: n > RL_LIMIT };
  } catch (e) { console.error('rl: error', e && e.message); return { configured: true, error: true }; } // fail open
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
  const rl = await rateState(req);
  res.setHeader('X-RL-Configured', String(!!rl.configured));
  if (rl.error) res.setHeader('X-RL-Error', '1');
  if (rl.configured && typeof rl.count === 'number') {
    res.setHeader('X-RateLimit-Limit', RL_LIMIT);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, RL_LIMIT - rl.count));
  }
  if (rl.limited) return send(res, 429, { error: 'Rate limit exceeded — please slow down and try again in a few minutes.' });
  let body;
  try { body = await readBody(req); } catch (e) { if (e && e.message === 'toobig') return send(res, 413, { error: 'Body too large' }); return send(res, 400, { error: 'Invalid JSON body' }); }

  try {
    if (body.repo) {
      const parsed = parseRepo(body.repo);
      if (!parsed) return send(res, 400, { error: 'Provide a valid public GitHub repo URL: https://github.com/owner/name' });
      const { files, branch, truncated, totalCandidates } = await fetchRepoFiles(parsed);
      if (!files.length) return send(res, 422, { error: 'No scannable .sol/.js/.ts/.py files found (repo may be private or empty).' });
      const result = scanFiles(files);
      return send(res, 200, { ...result, source: `${parsed.owner}/${parsed.repo}@${branch}`, truncated, totalCandidates });
    }

    const codeStr = (body.code || '').toString();
    if (!codeStr.trim()) return send(res, 400, { error: 'Paste some code or provide a repo URL.' });
    if (codeStr.length > MAX_PASTE) return send(res, 413, { error: 'Snippet too large (200 KB max).' });
    const filename = (body.filename || 'snippet.js').toString().slice(0, 120);
    const result = scanFiles([{ path: filename, text: codeStr }]);
    return send(res, 200, { ...result, source: filename });
  } catch (e) {
    if (e && e.message === 'ratelimit') return send(res, 429, { error: 'GitHub API rate limit reached — try the Paste mode instead.' });
    return send(res, 500, { error: 'Scan failed.' }); // opaque on purpose
  }
};
