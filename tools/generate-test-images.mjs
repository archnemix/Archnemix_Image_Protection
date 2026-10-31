#!/usr/bin/env node
/**
 * Generate the demo gallery: 100 small synthetic images (gradients + shapes +
 * big index numbers, so scrambling/decoy tests have obvious pixel signal),
 * plus the deliberately-unprotected public copies used by the comparison demo.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const root = path.dirname(fileURLToPath(import.meta.url)) + '/..';
const galleryDir = path.join(root, 'demo-masters', 'gallery');
const publicDir = path.join(root, 'demo', 'public-unprotected');
fs.mkdirSync(galleryDir, { recursive: true });
fs.mkdirSync(publicDir, { recursive: true });

const COUNT = Number(process.env.GALLERY_COUNT || 100);
const W = 640, H = 420;

function svgFor(i) {
  const hue = (i * 37) % 360;
  const hue2 = (hue + 70) % 360;
  const label = String(i + 1).padStart(3, '0');
  const circles = Array.from({ length: 5 }, (_, k) => {
    const cx = 70 + ((i * 53 + k * 131) % 500);
    const cy = 60 + ((i * 29 + k * 83) % 300);
    const r = 22 + ((i * 13 + k * 31) % 60);
    return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="hsl(${(hue + k * 40) % 360} 85% 60%)" opacity="0.75"/>`;
  }).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="hsl(${hue} 75% 45%)"/><stop offset="1" stop-color="hsl(${hue2} 80% 30%)"/>
  </linearGradient></defs>
  <rect width="${W}" height="${H}" fill="url(#g)"/>${circles}
  <rect x="24" y="${H - 118}" width="330" height="88" rx="14" fill="black" opacity="0.45"/>
  <text x="44" y="${H - 46}" font-family="sans-serif" font-size="62" font-weight="bold" fill="white">IMG ${label}</text>
</svg>`;
}

let done = 0;
await Promise.all(Array.from({ length: COUNT }, async (_, i) => {
  const out = path.join(galleryDir, `gallery-${String(i + 1).padStart(3, '0')}.jpg`);
  if (!fs.existsSync(out)) {
    await sharp(Buffer.from(svgFor(i))).jpeg({ quality: 84 }).toFile(out);
  }
  done++;
}));
console.log(`✔ ${done} gallery images in demo-masters/gallery/`);

// Deliberately UNPROTECTED copies for the "steal this one easily" comparison.
for (const name of ['aurora-valley', 'neon-portrait', 'luxury-watch']) {
  const src = path.join(root, 'demo-masters', name + '.jpg');
  const dst = path.join(publicDir, name + '.jpg');
  if (fs.existsSync(src)) {
    await sharp(src).resize({ width: 1000, withoutEnlargement: true }).jpeg({ quality: 84 }).toFile(dst);
    console.log('✔ public (unprotected demo copy):', name);
  }
}
