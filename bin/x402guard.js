#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { scan } = require(path.join(__dirname, '..', 'src', 'scanner'));
const { renderText, renderHtml, renderJson } = require(path.join(__dirname, '..', 'src', 'report'));

function main() {
  const args = process.argv.slice(2);
  let target = '.', htmlOut = null, jsonOut = null, ciGate = true, excludes = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--html') htmlOut = args[++i];
    else if (a === '--json') jsonOut = args[++i];
    else if (a === '--exclude') excludes = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
    else if (a === '--no-gate') ciGate = false;
    else if (a === '-h' || a === '--help') {
      console.log(`x402guard — security scanner for x402 / agent-payment integrations

Usage:
  x402guard <path> [options]

Options:
  --html <file>   write an HTML report
  --json <file>   write a JSON report
  --exclude a,b   skip files whose path contains any of these substrings
  --no-gate       always exit 0 (don't fail CI on findings)
  -h, --help      show this help

Exit code is 1 when any critical/high finding is present (CI gate), else 0.`);
      process.exit(0);
    } else if (!a.startsWith('-')) target = a;
  }

  if (!fs.existsSync(target)) {
    console.error(`x402guard: path not found: ${target}`);
    process.exit(2);
  }

  const result = scan(target, { exclude: excludes });
  process.stdout.write(renderText(result, target));
  if (htmlOut) { fs.writeFileSync(htmlOut, renderHtml(result, target)); console.log(`  HTML report -> ${htmlOut}`); }
  if (jsonOut) { fs.writeFileSync(jsonOut, renderJson(result)); console.log(`  JSON report -> ${jsonOut}`); }

  const blocking = result.counts.critical + result.counts.high;
  process.exit(ciGate && blocking > 0 ? 1 : 0);
}

main();
