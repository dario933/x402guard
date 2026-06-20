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
  if (req.body) return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  return await new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > MAX_BODY) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function parseRepo(url) {
  const m = /^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec((url || '').trim());
  return m ? { owner: m[1], repo: m[2] } : null;
}

async function gh(path) {
  const r = await fetch('https://api.github.com' + path, { headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'x402guard-grader' } });
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
  const files = [];
  for (const n of wanted) {
    try {
      const raw = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${n.path}`, { headers: { 'User-Agent': 'x402guard-grader' } });
      if (raw.ok) files.push({ path: n.path, text: await raw.text() });
    } catch { /* skip unreadable file */ }
  }
  return { files, branch, truncated: all.length > MAX_REPO_FILES, totalCandidates: all.length };
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
  let body;
  try { body = await readBody(req); } catch { return send(res, 400, { error: 'Invalid JSON body' }); }

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
