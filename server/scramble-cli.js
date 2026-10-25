#!/usr/bin/env node
/**
 * Offline protector CLI: turn a master image into a scrambled .archx asset
 * you can host on any static CDN. The output is useless without the key.
 *
 *   npx archx-protect photo.jpg photo.archx --key "my-secret" --max-width 1400
 *   npx archx-protect photo.jpg photo.archx --encrypt        (generates an AES key)
 *   npx archx-protect ./masters ./protected --key "my-secret" (whole folder)
 */
import fs from 'node:fs';
import path from 'node:path';
import { scrambleImage, generateKeyBase64 } from './scramble-image.js';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out[name] = next; i++; }
      else out[name] = true;
    } else out._.push(a);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const [input, output] = args._;
if (!input || !output || args.help) {
  console.log(`Usage: archx-protect <input image|folder> <output .archx|folder> [options]
  --key <secret>       scramble key (required in spirit — use a long random one)
  --grid <n>           tiles per side (default 8)
  --max-width <px>     down-scale master to this width first (default 1600)
  --quality <1-100>    WebP quality (default 82)
  --encrypt            AES-GCM-encrypt the payload (prints the key — store it safely)`);
  process.exit(input ? 0 : 1);
}

const key = args.key || '';
if (!key) console.warn('⚠  No --key given: anyone can un-scramble with the default key. Pass --key "<long random>".');
const aesKey = args.encrypt ? generateKeyBase64() : null;
const opts = {
  key,
  grid: args.grid ? Number(args.grid) : 8,
  maxWidth: args['max-width'] ? Number(args['max-width']) : 1600,
  quality: args.quality ? Number(args.quality) : 82,
  aesKey,
};

async function protectOne(inPath, outPath) {
  const inputBytes = fs.readFileSync(inPath);
  const { bytes, header } = await scrambleImage(inputBytes, opts);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, bytes);
  console.log(`✔ ${inPath} -> ${outPath}  (${header.w}×${header.h}, grid ${header.grid}, ${(bytes.length / 1024).toFixed(0)} kB)`);
}

const stat = fs.statSync(input);
if (stat.isDirectory()) {
  const files = fs.readdirSync(input).filter((f) => /\.(jpe?g|png|webp|avif|tiff?)$/i.test(f));
  for (const f of files) {
    await protectOne(path.join(input, f), path.join(output, f.replace(/\.[^.]+$/, '') + '.archx'));
  }
} else {
  await protectOne(input, output);
}

console.log('\nUse it in the browser:');
console.log(`  Archx.load.image('#hero', '/protected/${path.basename(output).replace(/\.archx$/, '')}.archx', {`);
console.log(`    key: ${JSON.stringify(key)}${aesKey ? `,\n    aesKey: ${JSON.stringify(aesKey)}  // ← keep server-side / token-delivered in production` : ''}`);
console.log('  });');
if (aesKey) console.log('\n🔑 AES key (store it like a password):', aesKey);
