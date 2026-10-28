#!/usr/bin/env node
/**
 * Real-browser protection tests (headless Chromium via puppeteer-core +
 * @sparticuz/chromium, so no browser download is needed).
 * Boots the demo server on a test port and verifies, in an actual browser:
 * DOM hygiene, poisoned read-back, WebGL black read-back, split tiles,
 * interaction guards, risk reactions, print blackout, visual correctness,
 * network payload scrambling, and 100-image gallery performance.
 */
import { spawn, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';
import { buildArchxAssets } from '../server/build-assets.js';
import { decodeContainer } from '../src/scramble.js';
import { unscrambleImage } from '../server/scramble-image.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 4179;
const BASE = `http://127.0.0.1:${PORT}`;

let failures = 0;
let checks = 0;
function check(name, cond, detail = '') {
  checks++;
  if (cond) console.log(`  ✔ ${name}${detail ? ' — ' + detail : ''}`);
  else { failures++; console.log(`  ✘ FAIL: ${name}${detail ? ' — ' + detail : ''}`); }
}

/* ensure demo images exist */
if (!fs.existsSync(path.join(root, 'demo-masters/gallery/gallery-001.jpg'))) {
  execSync('node tools/generate-test-images.mjs', { cwd: root, stdio: 'inherit' });
}

/* Build a tiny precomputed catalog for the manifest/CDN-path checks. The
 * generated directory is removed in the finally block below. */
const protectedTestDir = path.join(root, 'demo', 'protected-test');
fs.rmSync(protectedTestDir, { recursive: true, force: true });
const browserCatalogBuild = await buildArchxAssets({
  images: {
    'aurora-valley': path.join(root, 'demo-masters', 'aurora-valley.jpg'),
    'neon-portrait': path.join(root, 'demo-masters', 'neon-portrait.jpg'),
  },
  outputDir: protectedTestDir,
  baseUrl: '/demo/protected-test/',
  widths: [320, 640, 960],
  maxWidth: 960,
  key: 'browser-manifest-test-key',
  quality: 88,
  jobs: 2,
  processing: { webpEffort: 0, webpSmartSubsample: false, resizeKernel: 'lanczos2', sharpConcurrency: 1 },
});

/* A second catalog with scramble plan v2 (128-bit seed) for the [8e] checks. */
const protectedTestDirV2 = path.join(root, 'demo', 'protected-test-v2');
fs.rmSync(protectedTestDirV2, { recursive: true, force: true });
await buildArchxAssets({
  images: { 'aurora-valley': path.join(root, 'demo-masters', 'aurora-valley.jpg') },
  outputDir: protectedTestDirV2,
  baseUrl: '/demo/protected-test-v2/',
  widths: [320],
  maxWidth: 320,
  key: 'browser-manifest-test-key',
  planVersion: 2,
  quality: 88,
  jobs: 1,
  processing: { webpEffort: 0, webpSmartSubsample: false, resizeKernel: 'lanczos2', sharpConcurrency: 1 },
});

/* boot server */
const server = spawn('node', ['server/demo-server.js'], {
  cwd: root, env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });
async function waitServer() {
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(BASE + '/test-harness.html'); if (r.ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('demo server did not start:\n' + serverLog);
}

/* launch browser */
const chromium = (await import('@sparticuz/chromium')).default;
const puppeteer = (await import('puppeteer-core')).default;
await waitServer();

/* @sparticuz/chromium ships its AL2023 shared libs (libnspr4/libnss3/…) as a
 * brotli tar. Outside Lambda they aren't auto-extracted, so do it ourselves
 * and point the dynamic loader at them. */
async function chromiumEnv() {
  const libDir = '/tmp/al2023/lib';
  try {
    if (!fs.existsSync(path.join(libDir, 'libnspr4.so'))) {
      const zlib = await import('node:zlib');
      const { pipeline } = await import('node:stream/promises');
      const br = path.join(root, 'node_modules/@sparticuz/chromium/bin/al2023.tar.br');
      await pipeline(fs.createReadStream(br), zlib.createBrotliDecompress(), fs.createWriteStream('/tmp/al2023.tar'));
      fs.mkdirSync('/tmp/al2023', { recursive: true });
      execSync('tar -xf /tmp/al2023.tar -C /tmp/al2023');
    }
    return { ...process.env, LD_LIBRARY_PATH: libDir + ':' + (process.env.LD_LIBRARY_PATH || '') };
  } catch { return process.env; }
}

const browser = await puppeteer.launch({
  executablePath: await chromium.executablePath(),
  // Real web security stays ON: CORS/origin-taint behavior under test is
  // exactly what production browsers enforce, and the Lambda-oriented
  // '--disable-web-security' bundled default would hide it.
  args: [...chromium.args.filter((a) => a !== '--disable-web-security'),
    '--no-sandbox', '--disable-dev-shm-usage', '--enable-unsafe-swiftshader'],
  headless: true,
  env: await chromiumEnv(),
});
const page = await browser.newPage();
await page.setViewport({ width: 1200, height: 900 });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push('pageerror: ' + e.message));
page.on('console', (m) => { if (m.type() === 'error') pageErrors.push('console: ' + m.text()); });
const proofTraffic = { mintProofKeys: 0, payloadProofs: 0, payloadRequests: 0 };
const scaleTraffic = { batchMints: 0, singleMints: 0, manifests: 0, assetPayloads: 0, assetPayloadNetwork: 0 };
page.on('request', (request) => {
  const url = request.url();
  const headers = request.headers();
  if (url.includes('/archx/tokens')) scaleTraffic.batchMints++;
  else if (url.includes('/archx/token/')) scaleTraffic.singleMints++;
  if (url.includes('/demo/protected-test/archx-manifest.json')) scaleTraffic.manifests++;
  if (url.includes('/demo/protected-test/') && url.includes('.archx')) scaleTraffic.assetPayloads++;
  if (url.includes('/archx/token/') && headers['x-archx-proof-key']) proofTraffic.mintProofKeys++;
  if (url.includes('/archx/i/')) {
    proofTraffic.payloadRequests++;
    if (headers['x-archx-proof']) proofTraffic.payloadProofs++;
  }
});
page.on('response', (response) => {
  const url = response.url();
  if (url.includes('/demo/protected-test/') && url.includes('.archx') &&
      response.status() === 200 && !response.fromCache()) {
    scaleTraffic.assetPayloadNetwork++;
  }
});

try {
  await page.goto(BASE + '/test-harness.html', { waitUntil: 'networkidle2', timeout: 60000 });
  await page.waitForFunction(() => window.__allLoaded === true, { timeout: 60000 });

  console.log('\n[1] DOM hygiene — nothing for scrapers/extensions to grab');
  const dom = await page.evaluate(() => ({
    imgCount: document.querySelectorAll('img').length,
    imgSrcs: [...document.querySelectorAll('img')].map((i) => i.getAttribute('src')),
    canvasInDocument: document.querySelectorAll('canvas').length,
    closedShadowRoot: document.querySelector('#t-closed').shadowRoot,
    shieldOuter: document.querySelector('#t-shield').outerHTML,
    anyAuroraInDom: document.body.innerHTML.includes('/archx/i/') || document.body.innerHTML.includes('t=eyJ'),
    loadedFlags: Object.fromEntries(Object.entries(window.__instances).map(([k, v]) => [k, v.loaded])),
  }));
  check('only the deliberately unprotected <img> exists', dom.imgCount === 1 && dom.imgSrcs[0].includes('public-unprotected'), JSON.stringify(dom.imgSrcs));
  check('no canvas reachable via document.querySelectorAll (shadow DOM)', dom.canvasInDocument === 0);
  check('closed shadow root hides internals from JS (shadowRoot === null)', dom.closedShadowRoot === null);
  check('protected host outerHTML contains no URL/src', !/src=|http|\.jpg|\.archx/.test(dom.shieldOuter), dom.shieldOuter.slice(0, 120));
  check('no signed image URL anywhere in body HTML', !dom.anyAuroraInDom);
  check('all 7 protected instances loaded', Object.values(dom.loadedFlags).every(Boolean) && Object.keys(dom.loadedFlags).length === 7, JSON.stringify(dom.loadedFlags));

  console.log('\n[1b] Encapsulation — scripts/extensions get no handle to internals');
  const encap = await page.evaluate(async () => {
    const closedHost = document.querySelector('#t-closed');
    const closed = window.__instances.closed;
    const host = document.createElement('div');
    host.style.cssText = 'width:200px;height:120px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, '/demo/public-unprotected/neon-portrait.jpg',
      { mode: 'shield', key: 'super-secret-key', aesKey: 'super-secret-aes', lazy: false });
    await inst.ready;
    const out = {
      hostExpando: closedHost.__archx,
      publicRegistry: window.Archx._instances,
      instanceCountType: typeof window.Archx.instanceCount,
      closedDebug: closed._debug(),
      closedCanvasProp: closed.canvas,
      secretKey: inst.options.key,
      secretAes: inst.options.aesKey,
      tempDebug: inst._debug(),
      configEchoKey: window.Archx.config().key,
    };
    inst.destroy();
    host.remove();
    return out;
  });
  check('no __archx expando is stamped on host elements', encap.hostExpando === undefined);
  check('no public instance registry is exposed (Archx._instances)', encap.publicRegistry === undefined && encap.instanceCountType === 'number');
  check('_debug() returns null unless the instance was created with debug:true', encap.closedDebug === null && encap.tempDebug === null);
  check('canvas is not reachable as a public instance property', encap.closedCanvasProp === undefined);
  check('option secrets are redacted from the public options view', encap.secretKey === '[redacted]' && encap.secretAes === '[redacted]');
  check('Archx.config() echo never leaks secrets', !encap.configEchoKey || encap.configEchoKey === '[redacted]');

  console.log('\n[2] Visual correctness — protected images actually display the picture');
  async function boxStats(selector) {
    const el = await page.$(selector);
    const shot = await el.screenshot();
    const { data, info } = await sharp(shot).removeAlpha().raw().toBuffer({ resolveWithObject: true });
    let mean = 0; for (let i = 0; i < data.length; i++) mean += data[i]; mean /= data.length;
    let variance = 0; for (let i = 0; i < data.length; i++) variance += (data[i] - mean) ** 2; variance /= data.length;
    return { mean, std: Math.sqrt(variance), w: info.width, h: info.height };
  }
  for (const [sel, label] of [['#t-lite', 'lite'], ['#t-shield', 'shield'], ['#t-vault', 'vault(WebGL)'], ['#t-fortress', 'fortress(lens idle, pixelated)'], ['#t-split', 'split'], ['#t-clientonly', 'client-only']]) {
    const s = await boxStats(sel);
    check(`${label} renders a real, non-blank picture`, s.std > 18 && s.mean > 12, `mean=${s.mean.toFixed(1)} std=${s.std.toFixed(1)}`);
  }
  // Shield (scrambled delivery, unscrambled client-side) should resemble the normal <img> of same photo
  async function boxRaw(selector, w = 96, h = 64) {
    const el = await page.$(selector);
    return sharp(await el.screenshot()).resize(w, h).removeAlpha().raw().toBuffer();
  }
  const diffShieldVsNormal = (() => null)(); // placeholder to keep ordering clear
  const [rawNormal, rawShield] = [await boxRaw('#normal'), await boxRaw('#t-shield')];
  let mad = 0; for (let i = 0; i < rawNormal.length; i++) mad += Math.abs(rawNormal[i] - rawShield[i]);
  mad /= rawNormal.length;
  check('shield image matches the original photo visually (scramble round-trip in browser)', mad < 38, `mean abs diff=${mad.toFixed(1)} (watermark+re-encode tolerant)`);

  // Native-resolution detail retention: protection must not turn fine detail
  // into slurry. Compare the actual 340px renders, not a tiny thumbnail.
  async function boxNative(selector) {
    const el = await page.$(selector);
    const { data, info } = await sharp(await el.screenshot()).removeAlpha().raw().toBuffer({ resolveWithObject: true });
    let detail = 0;
    for (let y = 1; y < info.height - 1; y++) {
      for (let x = 1; x < info.width - 1; x++) {
        const i = (y * info.width + x) * 3;
        for (let c = 0; c < 3; c++) {
          detail += Math.abs(data[i + c] - data[i - 3 + c]) + Math.abs(data[i + c] - data[i - info.width * 3 + c]);
        }
      }
    }
    return { data, detail, w: info.width, h: info.height };
  }
  const [normalNative, shieldNative] = [await boxNative('#normal'), await boxNative('#t-shield')];
  let nativeMad = 0;
  for (let i = 0; i < normalNative.data.length; i++) nativeMad += Math.abs(normalNative.data[i] - shieldNative.data[i]);
  nativeMad /= normalNative.data.length;
  const detailRatio = shieldNative.detail / normalNative.detail;
  check('shield retains native rendered detail (no slurry from scramble/re-encode/resample)',
    nativeMad < 10 && detailRatio > 0.8,
    `native MAD=${nativeMad.toFixed(2)}, gradient-detail ratio=${detailRatio.toFixed(2)}`);

  console.log('\n[3] Poisoned read-back — canvas grabbers get decoys');
  const poison = await page.evaluate(async () => {
    const canvas = window.__instances.shield._debug().canvas;
    const dataUrl = canvas.toDataURL('image/png');
    const img = new Image();
    await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = dataUrl; });
    const probe = document.createElement('canvas');
    probe.width = img.width; probe.height = img.height;
    const pctx = probe.getContext('2d');
    pctx.drawImage(img, 0, 0);
    const px = pctx.getImageData(0, 0, probe.width, probe.height).data;
    let sum = 0; for (let i = 0; i < px.length; i += 4) sum += px[i] + px[i + 1] + px[i + 2];
    const decoyMean = sum / (px.length / 4) / 3;
    const blobText = await new Promise((res) => canvas.toBlob(async (b) => {
      const ab = new Uint8Array(await b.arrayBuffer()); res(ab.length);
    }, 'image/png'));
    const ctx = canvas.getContext('2d');
    const idata = ctx.getImageData(0, 0, 24, 24).data;
    let pixelSum = 0; for (let i = 0; i < idata.length; i += 4) pixelSum += idata[i] + idata[i + 1] + idata[i + 2];
    const attempts = window.__attempts.slice();
    return { decoyMean, blobBytes: blobText, getImageDataSum: pixelSum, attempts };
  });
  check('shield canvas.toDataURL() returns the black decoy (dark image)', poison.decoyMean < 22, `decoy mean brightness=${poison.decoyMean.toFixed(1)}/255`);
  check('shield canvas.toBlob() returns decoy bytes (not zero, not the photo pipeline)', poison.blobBytes > 800, `${poison.blobBytes} bytes`);
  check('shield ctx.getImageData() returns opaque black pixels', poison.getImageDataSum === 0);
  check('extraction attempts were reported via archx-attempt events',
    poison.attempts.includes('extract-dataurl') && poison.attempts.includes('extract-blob') && poison.attempts.includes('extract-pixels'),
    JSON.stringify([...new Set(poison.attempts)]));

  const scrambledDecoy = await page.evaluate(async () => {
    const host = document.createElement('div');
    host.style.cssText = 'width:300px;height:190px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'gallery-016' }, {
      mode: 'shield', debug: true, lazy: false, onExtract: 'scrambled', brand: 'TEST DECOY MARK',
    });
    await inst.ready;
    const canvas = inst._debug().canvas;
    const decode = async (url, w, h) => {
      const img = new Image();
      await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = url; });
      const probe = document.createElement('canvas');
      probe.width = w; probe.height = h;
      const ctx = probe.getContext('2d');
      ctx.drawImage(img, 0, 0, w, h);
      return ctx.getImageData(0, 0, w, h).data;
    };
    const cleanUrl = HTMLCanvasElement.prototype.toDataURL.call(canvas, 'image/png');
    const decoyUrl = canvas.toDataURL('image/png');
    const clean = await decode(cleanUrl, 160, 101);
    const decoy = await decode(decoyUrl, 160, 101);
    let diff = 0;
    let brightCenterPixels = 0;
    for (let y = 0; y < 101; y++) {
      for (let x = 0; x < 160; x++) {
        const i = (y * 160 + x) * 4;
        diff += Math.abs(clean[i] - decoy[i]) + Math.abs(clean[i + 1] - decoy[i + 1]) + Math.abs(clean[i + 2] - decoy[i + 2]);
        if (y > 35 && y < 66 && decoy[i] > 245 && decoy[i + 1] > 245 && decoy[i + 2] > 245) brightCenterPixels++;
      }
    }
    const out = {
      loaded: inst.loaded,
      mad: diff / (160 * 101) / 3,
      brightCenterPixels,
      decoyBytes: decoyUrl.length,
    };
    inst.destroy(); host.remove();
    return out;
  });
  check('scrambled decoy is materially unlike the clean displayed derivative and carries a visible center mark',
    scrambledDecoy.loaded && scrambledDecoy.mad > 18 && scrambledDecoy.brightCenterPixels > 20,
    JSON.stringify(scrambledDecoy));

  console.log('\n[4] Vault (WebGL) — even the prototype bypass gets black');
  const vaultBypass = await page.evaluate(async () => {
    const canvas = window.__instances.vault._debug().canvas;
    const real = HTMLCanvasElement.prototype.toDataURL;
    // Sample like an extension/script would: from a timer task, after frames presented.
    let best = null;
    for (let tries = 0; tries < 5; tries++) {
      await new Promise((r) => setTimeout(r, 90));
      const url = real.call(canvas, 'image/png');
      const img = new Image();
      await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = url; });
      const probe = document.createElement('canvas');
      probe.width = Math.max(1, img.width); probe.height = Math.max(1, img.height);
      const pctx = probe.getContext('2d');
      pctx.drawImage(img, 0, 0);
      const px = pctx.getImageData(0, 0, probe.width, probe.height).data;
      // RGB only — opaque black (0,0,0,255) must score 0, not 63.75.
      let sum = 0; for (let i = 0; i < px.length; i += 4) sum += px[i] + px[i + 1] + px[i + 2];
      const mean = sum / (px.length / 4) / 3;
      best = best === null ? mean : Math.min(best, mean);
      if (mean < 4) break;
    }
    // Shield prototype bypass for honest comparison (display-size watermarked copy)
    const shieldCanvas = window.__instances.shield._debug().canvas;
    const sUrl = real.call(shieldCanvas, 'image/png');
    const sImg = new Image();
    await new Promise((res, rej) => { sImg.onload = res; sImg.onerror = rej; sImg.src = sUrl; });
    return { vaultMean: best, vaultIsGL: !!window.__instances.vault._debug().canvas.getContext('webgl2', {}), shieldBypassW: sImg.width, shieldCanvasW: shieldCanvas.width };
  });
  check('vault prototype-bypass toDataURL is black/transparent', vaultBypass.vaultMean < 4, `mean=${vaultBypass.vaultMean.toFixed(2)}/255`);
  check('shield prototype bypass only yields the display-size backing store (resolution cap)', vaultBypass.shieldBypassW === vaultBypass.shieldCanvasW && vaultBypass.shieldCanvasW <= 700,
    `backing=${vaultBypass.shieldCanvasW}px wide for a 340px box (no master resolution)`);

  console.log('\n[5] Split-canvas mode — no single canvas holds the whole image');
  const split = await page.evaluate(() => ({
    tiles: window.__instances.split._debug().tiles.length,
    tilePoisoned: (() => {
      const t = window.__instances.split._debug().tiles[0];
      return t.toDataURL('image/png').length > 100; // decoy still returned
    })(),
  }));
  check('split mode renders 3×3 = 9 separate tile canvases', split.tiles === 9);
  check('each tile canvas is individually poisoned', split.tilePoisoned);

  console.log('\n[6] Interaction guards — right-click & drag');
  await page.evaluate(() => { window.__attempts.length = 0; });
  const shieldBox = await (await page.$('#t-shield')).boundingBox();
  await page.mouse.click(shieldBox.x + shieldBox.width / 2, shieldBox.y + shieldBox.height / 2, { button: 'right' });
  await new Promise((r) => setTimeout(r, 250));
  let attemptsNow = await page.evaluate(() => window.__attempts.slice());
  check('real right-click on protected image is intercepted (contextmenu)', attemptsNow.includes('contextmenu'), JSON.stringify(attemptsNow));
  const dragPrevented = await page.evaluate(() => {
    const wrap = window.__instances.shield._debug().wrap;
    const ev = new DragEvent('dragstart', { bubbles: true, cancelable: true });
    wrap.dispatchEvent(ev);
    return ev.defaultPrevented;
  });
  check('dragstart is prevented', dragPrevented === true);

  console.log('\n[7] Risk reactions — blur on window blur, print blackout');
  const blurState = await page.evaluate(() => {
    window.dispatchEvent(new Event('blur'));
    const on = window.__instances.shield._debug().wrap.classList.contains('risk-on');
    window.dispatchEvent(new Event('focus'));
    const off = window.__instances.shield._debug().wrap.classList.contains('risk-on');
    return { on, off };
  });
  check('window blur triggers protective blur; focus restores', blurState.on === true && blurState.off === false);
  await page.emulateMediaType('print');
  await new Promise((r) => setTimeout(r, 300));
  const printStats = await boxStats('#t-shield');
  check('print media renders protected image blacked out', printStats.mean < 16, `print mean=${printStats.mean.toFixed(1)}`);
  await page.emulateMediaType('screen');
  await new Promise((r) => setTimeout(r, 300));

  console.log('\n[7b] Fortress — lens, strict memory, local scramble, strikes, integrity lock');
  const fortressBox = await (await page.$('#t-fortress')).boundingBox();
  await page.mouse.move(fortressBox.x + fortressBox.width / 2, fortressBox.y + fortressBox.height / 2);
  await new Promise((r) => setTimeout(r, 250));
  const lensState = await page.evaluate(() => {
    const dbg = window.__instances.fortress._debug();
    const shield = dbg.wrap.querySelector('.shield');
    const before = dbg.lens ? { ...dbg.lens } : null;
    // Synthetic (script-fired) pointer events are untrusted and must be ignored.
    shield.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, clientX: 1, clientY: 1 }));
    const afterSynthetic = window.__instances.fortress._debug().lens;
    return {
      before,
      afterSynthetic,
      bitmapReleased: dbg.bitmapReleased,
      glScrambled: dbg.glScrambledTexture,
      captureTraceOn: dbg.captureTraceOn,
      traceText: dbg.traceText,
      temporalOn: dbg.temporalOn,
      glContinuous: dbg.glContinuous,
    };
  });
  check('trusted pointer input activates the fortress lens near the pointer',
    lensState.before && Math.abs(lensState.before.x - 0.5) < 0.25 && Math.abs(lensState.before.y - 0.5) < 0.25,
    JSON.stringify(lensState.before));
  check('synthetic (untrusted) pointer events cannot sweep the lens',
    JSON.stringify(lensState.afterSynthetic) === JSON.stringify(lensState.before));
  check('fortress strict-memory released the decoded bitmap after upload', lensState.bitmapReleased === true);
  check('fortress GPU texture is scrambled', lensState.glScrambled === true);
  check('fortress dynamic capture trace is active for OS/extension/camera captures',
    lensState.captureTraceOn === true && /TEST/.test(lensState.traceText || ''),
    (lensState.traceText || '').slice(0, 80));
  check('fortress temporal shield is active (single-frame captures get one noisy complementary frame)',
    lensState.temporalOn === true && lensState.glContinuous === true, JSON.stringify(lensState));

  const renderEconomy = await page.evaluate(async () => {
    const vault = window.__instances.vault._debug();
    const fortress = window.__instances.fortress._debug();
    const before = { vault: vault.glFrames, fortress: fortress.glFrames };
    await new Promise((r) => setTimeout(r, 450));
    const after = {
      vault: window.__instances.vault._debug().glFrames,
      fortress: window.__instances.fortress._debug().glFrames,
    };
    return {
      vaultDelta: after.vault - before.vault,
      fortressDelta: after.fortress - before.fortress,
      vaultContinuous: window.__instances.vault._debug().glContinuous,
    };
  });
  check('static Vault WebGL draws on demand instead of burning GPU at 60fps',
    renderEconomy.vaultContinuous === false && renderEconomy.vaultDelta <= 2,
    JSON.stringify(renderEconomy));
  check('temporal-shield Fortress is the deliberate exception that keeps animating',
    renderEconomy.fortressDelta > 5, JSON.stringify(renderEconomy));

  const captureKey = await page.evaluate(() => {
    window.__attempts.length = 0;
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'PrintScreen', code: 'PrintScreen', bubbles: true }));
    const dbg = window.__instances.shield._debug();
    return { blackout: dbg.wrap.classList.contains('blackout'), attempts: window.__attempts.slice() };
  });
  check('screenshot-key signal immediately blackouts protected images',
    captureKey.blackout === true && captureKey.attempts.includes('screenshot-key'),
    JSON.stringify(captureKey));
  await new Promise((r) => setTimeout(r, 1300)); // let the momentary blackout expire

  const localScramble = await page.evaluate(async () => {
    const host = document.createElement('div');
    host.style.cssText = 'width:300px;height:190px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, '/demo/public-unprotected/neon-portrait.jpg',
      { mode: 'fortress', debug: true, lazy: false, automation: 'monitor', lens: false });
    await inst.ready;
    await new Promise((r) => setTimeout(r, 250));
    const dbg = inst._debug();
    const out = { loaded: inst.loaded, glScrambled: dbg?.glScrambledTexture, released: dbg?.bitmapReleased };
    inst.destroy(); host.remove();
    return out;
  });
  check('plain client-only source is locally scrambled before GPU upload in fortress',
    localScramble.loaded && localScramble.glScrambled === true && localScramble.released === true, JSON.stringify(localScramble));

  const noReload = await page.evaluate(async () => {
    const count = (needle) => performance.getEntriesByType('resource')
      .filter((e) => e.name.includes(needle)).length;
    const host = document.createElement('div');
    host.style.cssText = 'width:300px;height:190px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'gallery-006' }, {
      mode: 'fortress', debug: true, lazy: false, automation: 'monitor',
      unloadOnExit: true, temporalShield: false,
    });
    await inst.ready;
    await new Promise((r) => setTimeout(r, 200));
    const before = {
      tokens: count('/archx/token/gallery-006'),
      payloads: count('/archx/i/gallery-006'),
      cachedPayload: inst._debug().cachedPayload,
      released: inst._debug().bitmapReleased,
    };
    // Scroll out/in and an ordinary resize: repaint locally, never remint.
    inst._onVisibility(false);
    inst._onVisibility(true);
    host.style.width = '336px';
    await new Promise((r) => setTimeout(r, 350));
    const after = {
      tokens: count('/archx/token/gallery-006'),
      payloads: count('/archx/i/gallery-006'),
      loaded: inst.loaded,
      loadedOnce: inst._debug().loadedOnce,
    };
    inst.destroy(); host.remove();
    return { before, after };
  });
  check('a loaded strict-memory image does not reload/remint on visibility or ordinary resize',
    noReload.before.tokens === 1 && noReload.after.tokens === 1 &&
    noReload.before.payloads === 1 && noReload.after.payloads === 1 &&
    noReload.before.cachedPayload === true && noReload.after.loadedOnce === true,
    JSON.stringify(noReload));

  const presetInfo = await page.evaluate(() => {
    const p = window.Archx.preset('screenshotResistant', { temporalShield: false, renderLoop: 'static' });
    return {
      names: Object.keys(window.Archx.presets),
      mode: p.mode,
      temporalOff: p.temporalShield === false,
      loop: p.renderLoop,
      quality: p.qualityProfile,
    };
  });
  check('direct parameter presets are inspectable and individually overridable',
    presetInfo.names.includes('gallery') && presetInfo.names.includes('commerce') &&
    presetInfo.mode === 'fortress' && presetInfo.temporalOff && presetInfo.loop === 'static',
    JSON.stringify(presetInfo));

  const customFlags = await page.evaluate(async () => {
    async function make(id, options) {
      const host = document.createElement('div');
      host.style.cssText = 'width:300px;height:190px';
      document.body.appendChild(host);
      const inst = window.Archx.load.image(host, { id }, { debug: true, lazy: false, ...options });
      await inst.ready;
      await new Promise((r) => setTimeout(r, 120)); // let a static WebGL presentation frame run
      const out = {
        loaded: inst.loaded,
        requestedMode: inst.options.requestedMode,
        resolvedMode: inst.options.mode,
        renderer: inst.options.renderer,
        forensic: inst.options.forensic,
        memory: inst.options.memory,
        tiles: inst._debug().tiles.length,
        glFrames: inst._debug().glFrames,
        bitmapReleased: inst._debug().bitmapReleased,
      };
      inst.destroy(); host.remove();
      return out;
    }

    const explicitCustom = await make('gallery-006', {
      mode: 'custom', renderer: 'canvas', splitCanvases: true, splitGrid: 3,
      forensic: true, memory: 'standard', temporalShield: false,
    });
    const noModeCustom = await make('gallery-007', {
      renderer: 'webgl', forensic: true, memory: 'strict', localScramble: true,
      temporalShield: false, renderLoop: 'static',
    });
    return { explicitCustom, noModeCustom };
  });
  check('custom flags work without a preset mode (explicit custom + omitted mode)',
    customFlags.explicitCustom.loaded && customFlags.explicitCustom.requestedMode === 'custom' &&
    customFlags.explicitCustom.renderer === 'canvas' && customFlags.explicitCustom.tiles === 9 &&
    customFlags.noModeCustom.loaded && customFlags.noModeCustom.requestedMode === 'custom' &&
    customFlags.noModeCustom.renderer === 'webgl' && customFlags.noModeCustom.resolvedMode === 'vault' &&
    customFlags.noModeCustom.glFrames > 0 && customFlags.noModeCustom.memory === 'strict',
    JSON.stringify(customFlags));

  const cameraShield = await page.evaluate(async () => {
    async function make(id, options) {
      const host = document.createElement('div');
      host.style.cssText = 'width:300px;height:190px';
      document.body.appendChild(host);
      const inst = window.Archx.load.image(host, { id }, {
        mode: 'custom', debug: true, lazy: false, cacheScope: 'camera-test', ...options,
      });
      await inst.ready;
      const before = inst._debug().glFrames;
      // Poll for frame advancement instead of a fixed 250 ms window: the
      // one-time preserveDrawingBuffer canary legitimately holds two
      // frames after the first presented frame, and under SwiftShader the
      // first frame itself can land late — a fixed window flakes.
      let dbg = inst._debug();
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && dbg.glFrames - before <= 2 && dbg.glContinuous) {
        await new Promise((r) => setTimeout(r, 100));
        dbg = inst._debug();
      }
      const out = {
        loaded: inst.loaded,
        pattern: dbg.temporalPattern,
        chroma: dbg.temporalChroma,
        temporalOn: dbg.temporalOn,
        frames2d: dbg.temporalFrames2d,
        glContinuous: dbg.glContinuous,
        glDelta: dbg.glFrames - before,
        tokenMethod: dbg.tokenMethod,
        cacheScope: dbg.cacheScope,
        cacheScopeSet: dbg.cacheScopeSet,
      };
      inst.destroy(); host.remove();
      return out;
    }
    const webgl = await make('gallery-008', {
      renderer: 'webgl',
      cameraShield: { pattern: 'bands', chroma: true, strength: 0.14, block: 3 },
    });
    const canvas = await make('gallery-009', {
      renderer: 'canvas',
      cameraShield: { pattern: 'checker', chroma: true, strength: 0.12, block: 3 },
    });
    window.Archx.clearCaches();
    return { webgl, canvas, vaultStillLoaded: window.__instances.vault.loaded };
  });
  check('camera shield drives patterned opponent-colour temporal frames in WebGL and Canvas2D',
    cameraShield.webgl.loaded && cameraShield.webgl.pattern === 'bands' && cameraShield.webgl.chroma &&
    cameraShield.webgl.glContinuous && cameraShield.webgl.glDelta > 2 &&
    cameraShield.canvas.loaded && cameraShield.canvas.pattern === 'checker' && cameraShield.canvas.chroma &&
    cameraShield.canvas.frames2d && cameraShield.webgl.tokenMethod === 'POST' &&
    cameraShield.canvas.cacheScope === undefined && cameraShield.canvas.cacheScopeSet === true &&
    cameraShield.vaultStillLoaded,
    JSON.stringify(cameraShield));

  console.log('\n[7b2] Temporal interlace — shader and pre-rendered phase engines');
  const temporalInterlace = await page.evaluate(async () => {
    async function make(id, options, keep = false) {
      const host = document.createElement('div');
      host.style.cssText = 'width:300px;height:190px';
      document.body.appendChild(host);
      const inst = window.Archx.load.image(host, { id }, {
        mode: 'custom', debug: true, lazy: false, cacheScope: 'temporal-interlace-test', ...options,
      });
      await inst.ready;
      const beforeDbg = inst._debug();
      const before = beforeDbg.glFrames;
      const beforeIndex = beforeDbg.temporalIndex;
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const now = inst._debug();
        const advanced = now.temporalEngineActual === 'shader'
          ? now.glFrames - before > 2
          : now.temporalIndex - beforeIndex > 2;
        if (advanced) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      const dbg = inst._debug();
      const out = {
        loaded: inst.loaded,
        engineRequested: dbg.temporalEngineRequested,
        engineActual: dbg.temporalEngineActual,
        interlace: dbg.temporalInterlace,
        frameCount: dbg.temporalFrameCount,
        frames2d: dbg.temporalFrames2d,
        glContinuous: dbg.glContinuous,
        glDelta: dbg.glFrames - before,
      };
      if (keep) {
        host.id = 'temporal-interlace-shot';
        window.__temporalInterlaceShot = { host, inst };
      } else {
        inst.destroy(); host.remove();
      }
      return out;
    }

    const shaderPixels = await make('gallery-010', {
      temporalInterlace: {
        profile: 'pixels60', engine: 'shader', phases: 4, refreshHz: 60, fill: 'black', activeGain: 1,
      },
    });
    const frameStrips = await make('gallery-011', {
      temporalInterlace: {
        profile: 'strips60', engine: 'frames', fill: 'black', activeGain: 1,
      },
    }, true);
    const frameBlocks = await make('gallery-012', {
      temporalInterlace: {
        profile: 'blocks60', engine: 'frames', phases: 3, refreshHz: 90,
        fill: 'dim', hiddenScale: 0.2,
      },
    });
    const shaderLens = await make('gallery-013', {
      lens: true,
      temporalInterlace: { engine: 'shader' },
    });
    const frameLens = await make('gallery-014', {
      lens: true,
      temporalInterlace: { engine: 'frames', layout: 'checker' },
    });
    const fortress60 = await make('gallery-015', {
      temporalInterlace: { profile: 'fortress60', engine: 'frames' },
    });
    return { shaderPixels, frameStrips, frameBlocks, shaderLens, frameLens, fortress60 };
  });
  const interlaceShotEl = await page.$('#temporal-interlace-shot');
  const phaseShots = [];
  const phaseSamples = [];
  let maxPhaseMad = 0;
  // A fixed screenshot cadence can parity-lock onto the same phase on a
  // fast/slow CI compositor. Use irregular intervals and stop as soon as two
  // real captures prove that different incomplete phases were presented.
  for (const delay of [0, 17, 31, 47, 67, 89, 113, 139, 167, 197]) {
    if (delay) await new Promise((r) => setTimeout(r, delay));
    phaseSamples.push(await page.evaluate(async () => {
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const dbg = window.__temporalInterlaceShot.inst._debug();
      return { index: dbg.temporalIndex, phase: dbg.temporalPhase };
    }));
    const shot = await sharp(await interlaceShotEl.screenshot()).removeAlpha().raw().toBuffer();
    for (const previous of phaseShots) {
      let diff = 0;
      const len = Math.min(previous.length, shot.length);
      for (let i = 0; i < len; i++) diff += Math.abs(previous[i] - shot[i]);
      maxPhaseMad = Math.max(maxPhaseMad, diff / len);
    }
    phaseShots.push(shot);
    if (maxPhaseMad > 8) break;
  }
  await page.evaluate(() => {
    const held = window.__temporalInterlaceShot;
    held?.inst.destroy();
    held?.host.remove();
    delete window.__temporalInterlaceShot;
  });
  check('GPU temporal-interlace uses the shader engine and clamps 4 requested phases to 2 at 60 Hz',
    temporalInterlace.shaderPixels.loaded &&
    temporalInterlace.shaderPixels.engineRequested === 'shader' &&
    temporalInterlace.shaderPixels.engineActual === 'shader' &&
    temporalInterlace.shaderPixels.interlace.layout === 'pixels' &&
    temporalInterlace.shaderPixels.interlace.requestedPhases === 4 &&
    temporalInterlace.shaderPixels.interlace.phases === 2 &&
    temporalInterlace.shaderPixels.interlace.phaseHz === 30 &&
    temporalInterlace.shaderPixels.glContinuous &&
    temporalInterlace.shaderPixels.glDelta > 2,
    JSON.stringify(temporalInterlace.shaderPixels));
  check('Canvas temporal-interlace pre-renders strip and multi-phase block frame sets',
    temporalInterlace.frameStrips.loaded &&
    temporalInterlace.frameStrips.engineActual === 'frames' &&
    temporalInterlace.frameStrips.frameCount === 2 &&
    temporalInterlace.frameBlocks.loaded &&
    temporalInterlace.frameBlocks.engineActual === 'frames' &&
    temporalInterlace.frameBlocks.interlace.layout === 'blocks' &&
    temporalInterlace.frameBlocks.frameCount === 3 &&
    temporalInterlace.frameBlocks.interlace.phases === 3,
    JSON.stringify({ strips: temporalInterlace.frameStrips, blocks: temporalInterlace.frameBlocks }));
  check('successive real screenshots receive materially different interlace phases',
    maxPhaseMad > 8, `max phase MAD=${maxPhaseMad.toFixed(1)} samples=${JSON.stringify(phaseSamples)}`);
  check('Lens composes with both temporal-interlace engines instead of silently disabling interlace',
    temporalInterlace.shaderLens.loaded &&
    temporalInterlace.shaderLens.engineActual === 'shader' &&
    temporalInterlace.shaderLens.glDelta > 2 &&
    temporalInterlace.frameLens.loaded &&
    temporalInterlace.frameLens.engineActual === 'frames' &&
    temporalInterlace.frameLens.frameCount === 2,
    JSON.stringify({ shaderLens: temporalInterlace.shaderLens, frameLens: temporalInterlace.frameLens }));
  check('fortress60 uses three 20 Hz subsets with noise-filled hidden blocks',
    temporalInterlace.fortress60.loaded &&
    temporalInterlace.fortress60.engineActual === 'frames' &&
    temporalInterlace.fortress60.frameCount === 3 &&
    temporalInterlace.fortress60.interlace.profile === 'fortress60' &&
    temporalInterlace.fortress60.interlace.phases === 3 &&
    temporalInterlace.fortress60.interlace.phaseHz === 20 &&
    temporalInterlace.fortress60.interlace.layout === 'blocks' &&
    temporalInterlace.fortress60.interlace.fill === 'noise',
    JSON.stringify(temporalInterlace.fortress60));

  console.log('\n[7c] v1.5 client fail-closed boundaries');
  const v15Client = await page.evaluate(async () => {
    const shield = window.__instances.shield;
    const view = shield.options;
    view.guards.contextMenu = false;
    view.mode = 'lite';
    view.key = 'attacker-controlled';

    let duplicateError = '';
    try {
      window.Archx.load.image(shield.element, '/demo/public-unprotected/neon-portrait.jpg', { lazy: false });
    } catch (err) { duplicateError = err.message; }

    const shadowHost = document.createElement('div');
    shadowHost.style.cssText = 'width:200px;height:120px';
    document.body.appendChild(shadowHost);
    shadowHost.attachShadow({ mode: 'closed' });
    let shadowError = '';
    try {
      window.Archx.load.image(shadowHost, '/demo/public-unprotected/neon-portrait.jpg', { lazy: false });
    } catch (err) { shadowError = err.message; }
    shadowHost.remove();

    const badHost = document.createElement('div');
    badHost.style.cssText = 'width:200px;height:120px';
    document.body.appendChild(badHost);
    const bad = window.Archx.load.image(
      badHost,
      new Blob(['<svg xmlns="http://www.w3.org/2000/svg" width="9999" height="9999"></svg>'], { type: 'image/svg+xml' }),
      { lazy: false },
    );
    await bad.ready;
    const badLoaded = bad.loaded;
    bad.destroy(); badHost.remove();

    const payloadNames = performance.getEntriesByType('resource')
      .map((entry) => entry.name)
      .filter((name) => name.includes('/archx/i/'));
    return {
      duplicateError,
      shadowError,
      badLoaded,
      optionsStillShield: shield.options.mode,
      contextMenuStillGuarded: shield.options.guards.contextMenu,
      keyStillRedacted: shield.options.key || null,
      payloadCount: payloadNames.length,
      payloadQueryTokens: payloadNames.filter((name) => name.includes('?t=') || name.includes('&t=')).length,
    };
  });
  check('a second live Archx instance cannot hijack an existing host element',
    /already hosts a live protected image/.test(v15Client.duplicateError), v15Client.duplicateError);
  check('an unavailable requested shadow root fails closed instead of falling back to light DOM',
    /unable to attach the requested shadow root/.test(v15Client.shadowError), v15Client.shadowError);
  check('unsupported SVG payload is rejected before browser image decode', v15Client.badLoaded === false);
  check('public options view is a deep clone; mutating it cannot weaken live guards',
    v15Client.optionsStillShield === 'shield' && v15Client.contextMenuStillGuarded === true);
  check('browser payload requests use clean URLs with no bearer token in Resource Timing names',
    v15Client.payloadCount > 0 && v15Client.payloadQueryTokens === 0, JSON.stringify(v15Client));
  check('browser token traffic is sender-constrained with a page proof key and per-payload proof',
    proofTraffic.mintProofKeys > 0 && proofTraffic.payloadRequests > 0 &&
    proofTraffic.payloadProofs === proofTraffic.payloadRequests,
    JSON.stringify(proofTraffic));

  const strike = await page.evaluate(async () => {
    window.__attempts.length = 0;
    const host = document.createElement('div');
    host.style.cssText = 'width:300px;height:190px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'gallery-004' },
      { mode: 'shield', debug: true, lazy: false, strikes: { blurAt: 99, lockAt: 2, lockMs: 1500 } });
    await inst.ready;
    const canvas = inst._debug().canvas;
    canvas.toDataURL('image/png');
    canvas.toDataURL('image/png');
    const dbg = inst._debug();
    const out = { locked: dbg.locked, strikes: dbg.strikes, blackout: dbg.wrap.classList.contains('blackout') };
    inst.destroy(); host.remove();
    return out;
  });
  check('repeated extraction attempts escalate to a strike lockout (blackout)',
    strike.locked === true && strike.blackout === true && strike.strikes >= 2, JSON.stringify(strike));

  const integrity = await page.evaluate(async () => {
    window.__attempts.length = 0;
    const originalFetch = window.fetch;
    window.fetch = (...args) => originalFetch(...args); // naive userscript-style hook
    const host = document.createElement('div');
    host.style.cssText = 'width:300px;height:190px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'gallery-005' },
      { mode: 'fortress', debug: true, lazy: false, automation: 'monitor' });
    await inst.ready;
    await new Promise((r) => setTimeout(r, 150));
    const dbg = inst._debug();
    const out = {
      loaded: inst.loaded,
      issues: dbg?.integrityIssues || [],
      attempts: window.__attempts.slice(),
      auditNow: window.Archx.auditIntegrity(),
    };
    window.fetch = originalFetch;
    inst.destroy(); host.remove();
    return out;
  });
  check('hooked fetch is detected by the integrity audit', integrity.auditNow.includes('fetch'), JSON.stringify(integrity.auditNow));
  check('fortress integrity policy fails closed (image does not load) under API hooking',
    integrity.loaded === false && integrity.issues.includes('fetch') && integrity.attempts.some((a) => a.startsWith('integrity')),
    JSON.stringify(integrity));
  const integrityRestored = await page.evaluate(() => window.Archx.auditIntegrity());
  check('integrity audit is clean again after restoring the native fetch', integrityRestored.length === 0, JSON.stringify(integrityRestored));

  const webglIntegrity = await page.evaluate(async () => {
    const events = [];
    const pluginEvents = [];
    const unsubscribe = window.Archx.on((event) => { events.push(event); });
    const plugin = window.Archx.use({
      name: 'browser-test-plugin',
      onEvent: (event) => { pluginEvents.push(event.type); },
    });
    const prototypes = [
      typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype : null,
      typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype : null,
    ].filter(Boolean);
    const saved = prototypes.map((proto) => ({
      proto,
      drawArrays: proto.drawArrays,
      drawElements: proto.drawElements,
    }));
    for (const entry of saved) {
      entry.proto.drawArrays = function (...args) { return entry.drawArrays.apply(this, args); };
      entry.proto.drawElements = function (...args) { return entry.drawElements.apply(this, args); };
    }
    const details = window.Archx.auditIntegrityDetails();
    const makeHost = () => {
      const host = document.createElement('div');
      host.style.cssText = 'width:300px;height:190px';
      document.body.appendChild(host);
      return host;
    };
    const fortressHost = makeHost();
    const fortress = window.Archx.load.image(fortressHost, { id: 'gallery-006' }, {
      mode: 'fortress', debug: true, lazy: false, automation: 'monitor',
    });
    await fortress.ready;
    await new Promise((r) => setTimeout(r, 120));
    const fortressResult = {
      loaded: fortress.loaded,
      issues: fortress._debug()?.integrityIssues || [],
    };
    fortress.destroy(); fortressHost.remove();

    const vaultHost = makeHost();
    const vault = window.Archx.load.image(vaultHost, { id: 'gallery-007' }, {
      mode: 'vault', integrity: 'monitor', debug: true, lazy: false, automation: 'monitor',
    });
    await vault.ready;
    await new Promise((r) => setTimeout(r, 180));
    const vaultResult = {
      loaded: vault.loaded,
      issues: vault._debug()?.integrityIssues || [],
    };
    vault.destroy(); vaultHost.remove();

    for (const entry of saved) {
      entry.proto.drawArrays = entry.drawArrays;
      entry.proto.drawElements = entry.drawElements;
    }

    const invalidHost = makeHost();
    const invalid = window.Archx.load.image(invalidHost, { id: 'gallery-008' }, {
      mode: 'shield', integrity: 'bogus', debug: true, lazy: false, automation: 'monitor',
    });
    await invalid.ready;
    await new Promise((r) => setTimeout(r, 120));
    const invalidResult = { loaded: invalid.loaded };
    invalid.destroy(); invalidHost.remove();

    const serializedEvents = JSON.stringify(events);
    const out = {
      auditIssues: window.Archx.auditIntegrity(),
      details,
      fortress: fortressResult,
      vault: vaultResult,
      invalid: invalidResult,
      eventTypes: events.map((event) => event.type),
      attemptKinds: events.filter((event) => event.type === 'archx.attempt').map((event) => event.kind),
      pluginEvents,
      eventKeys: [...new Set(events.flatMap((event) => Object.keys(event)))].sort(),
      serializedEvents,
    };
    plugin.remove();
    unsubscribe();
    return out;
  });
  check('WebGL drawArrays/drawElements hooks are named by the integrity audit',
    webglIntegrity.details.issues.some((name) => name.endsWith('.drawArrays')) &&
      webglIntegrity.details.issues.some((name) => name.endsWith('.drawElements')),
    JSON.stringify(webglIntegrity.details.issues));
  check('fortress fails closed under patched WebGL draw calls',
    webglIntegrity.fortress.loaded === false &&
      webglIntegrity.fortress.issues.some((name) => name.includes('draw')),
    JSON.stringify(webglIntegrity.fortress));
  check('vault monitor policy reports but continues under patched WebGL draw calls',
    webglIntegrity.vault.loaded === true &&
      webglIntegrity.vault.issues.some((name) => name.includes('draw')),
    JSON.stringify(webglIntegrity.vault));
  check('invalid integrity mode fails closed instead of becoming monitor-only',
    webglIntegrity.invalid.loaded === false &&
      webglIntegrity.attemptKinds.some((kind) => kind.includes('invalid-mode')),
    JSON.stringify(webglIntegrity.attemptKinds));
  check('global/plugin monitoring receives only sanitized event fields',
    webglIntegrity.pluginEvents.includes('archx.loaded') &&
      !webglIntegrity.eventKeys.some((key) => /token|key|aes|secret|bitmap|canvas|source/i.test(key)) &&
      !/gallery-00[678]/.test(webglIntegrity.serializedEvents),
    JSON.stringify({ keys: webglIntegrity.eventKeys, types: webglIntegrity.eventTypes }));
  check('WebGL integrity audit is clean after restoring draw methods',
    webglIntegrity.auditIssues.length === 0, JSON.stringify(webglIntegrity.auditIssues));

  // Reproduce the userscript ordering from the external review: this wrapper
  // is installed before /src/index.js is evaluated, so Archx captures the
  // wrapper itself as its drawArrays reference. The wrapper performs the
  // original draw and immediately samples the bound framebuffer.
  const hookPage = await browser.newPage();
  await hookPage.setViewport({ width: 900, height: 700 });
  const hookPageErrors = [];
  hookPage.on('pageerror', (e) => hookPageErrors.push(e.message));
  await hookPage.evaluateOnNewDocument(() => {
    const capture = {
      enabled: false,
      drawCalls: 0,
      sampledPixels: 0,
      nonBlackPixels: 0,
      maxChannel: 0,
      perDraw: [],
    };
    window.__archxPreloadCapture = capture;
    for (const ctor of [
      typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext : null,
      typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext : null,
    ].filter(Boolean)) {
      const proto = ctor.prototype;
      const originalDrawArrays = proto.drawArrays;
      const originalReadPixels = proto.readPixels;
      proto.drawArrays = function (...args) {
        const result = originalDrawArrays.apply(this, args);
        if (!capture.enabled) return result;
        capture.drawCalls++;
        // Per-draw records (canvas identity + local stats) so the test can
        // attribute frames to the instance under test: other live harness
        // demos may legitimately repaint during the measurement window
        // (layout shifts, unload/reload), and their frames must not be
        // charged to the fortress instance.
        const rec = { canvas: this.canvas || null, nonBlack: 0, max: 0 };
        capture.perDraw.push(rec);
        try {
          const width = Math.max(1, Math.min(16, this.drawingBufferWidth || 1));
          const height = Math.max(1, Math.min(16, this.drawingBufferHeight || 1));
          const x = Math.max(0, Math.floor(((this.drawingBufferWidth || width) - width) / 2));
          const y = Math.max(0, Math.floor(((this.drawingBufferHeight || height) - height) / 2));
          const pixels = new Uint8Array(width * height * 4);
          originalReadPixels.call(this, x, y, width, height, this.RGBA, this.UNSIGNED_BYTE, pixels);
          capture.sampledPixels += width * height;
          for (let i = 0; i < pixels.length; i += 4) {
            const max = Math.max(pixels[i], pixels[i + 1], pixels[i + 2]);
            if (max > capture.maxChannel) capture.maxChannel = max;
            if (max > rec.max) rec.max = max;
            if (max > 8) { capture.nonBlackPixels++; rec.nonBlack++; }
          }
        } catch {}
        return result;
      };
    }
  });
  await hookPage.goto(BASE + '/test-harness.html', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await hookPage.waitForFunction(() => window.__allLoaded === true, { timeout: 60000 });
  const preloadHook = await hookPage.evaluate(async () => {
    const capture = window.__archxPreloadCapture;
    const reset = () => Object.assign(capture, {
      enabled: true, drawCalls: 0, sampledPixels: 0, nonBlackPixels: 0, maxChannel: 0, perDraw: [],
    });
    // Stats restricted to one instance's own canvas (see perDraw note).
    const forCanvas = (canvas) => {
      const rows = canvas ? capture.perDraw.filter((d) => d.canvas === canvas) : [];
      return {
        drawCalls: rows.length,
        nonBlackPixels: rows.reduce((n, d) => n + d.nonBlack, 0),
        maxChannel: rows.reduce((m, d) => Math.max(m, d.max), 0),
        strayDraws: capture.perDraw.length - rows.length,
      };
    };
    const makeHost = () => {
      const host = document.createElement('div');
      host.style.cssText = 'width:320px;height:200px';
      document.body.appendChild(host);
      return host;
    };

    reset();
    const fortressHost = makeHost();
    const fortress = window.Archx.load.image(fortressHost, { id: 'gallery-009' }, {
      mode: 'fortress', debug: true, lazy: false, automation: 'monitor',
    });
    await fortress.ready;
    await new Promise((r) => setTimeout(r, 180));
    const fortressResult = {
      loaded: fortress.loaded,
      issues: fortress._debug()?.integrityIssues || [],
      capture: forCanvas(fortress._debug()?.canvas),
    };
    fortress.destroy(); fortressHost.remove();

    reset();
    const vaultHost = makeHost();
    const vault = window.Archx.load.image(vaultHost, { id: 'gallery-010' }, {
      mode: 'vault', integrity: 'monitor', debug: true, lazy: false, automation: 'monitor',
    });
    await vault.ready;
    await new Promise((r) => setTimeout(r, 250));
    const vaultResult = {
      loaded: vault.loaded,
      issues: vault._debug()?.integrityIssues || [],
      capture: forCanvas(vault._debug()?.canvas),
    };
    vault.destroy(); vaultHost.remove();
    capture.enabled = false;
    return {
      details: window.Archx.auditIntegrityDetails(),
      fortress: fortressResult,
      vault: vaultResult,
    };
  });
  await hookPage.close();
  check('pre-load drawArrays hook is Captured as non-native and fortress gives it no non-black frame',
    preloadHook.details.capturedNonNative.some((name) => name.endsWith('.drawArrays')) &&
      preloadHook.fortress.loaded === false &&
      preloadHook.fortress.issues.some((name) => name.endsWith('.drawArrays')) &&
      preloadHook.fortress.capture.nonBlackPixels === 0,
    JSON.stringify({ preloadHook, hookPageErrors }));
  check('documented residual risk: vault monitor renders while a pre-load drawArrays hook can read its framebuffer',
    preloadHook.vault.loaded === true &&
      preloadHook.vault.issues.some((name) => name.endsWith('.drawArrays')) &&
      preloadHook.vault.capture.drawCalls > 0 &&
      preloadHook.vault.capture.nonBlackPixels > 0 &&
      preloadHook.vault.capture.maxChannel > 32,
    JSON.stringify(preloadHook.vault));

  // v1.12 canary: a pre-load proxy forces preserveDrawingBuffer:true while
  // spoofing getContextAttributes to report false. The proxy is installed
  // before Archx loads, so the *captured* natives are the spoofed ones and
  // the attribute check is blind — only the behavioral readPixels canary
  // (painted pixels surviving past composite) can detect it. A monitor
  // instance isolates that path: preserveFlagged can only be set there.
  const spoofPage = await browser.newPage();
  await spoofPage.setViewport({ width: 900, height: 700 });
  const spoofErrors = [];
  spoofPage.on('pageerror', (e) => spoofErrors.push(e.message));
  await spoofPage.evaluateOnNewDocument(() => {
    const origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (type, attrs) {
      if (type === 'webgl2' || type === 'webgl' || type === 'experimental-webgl') {
        return origGetContext.call(this, type, { ...(attrs || {}), preserveDrawingBuffer: true });
      }
      return origGetContext.call(this, type, attrs);
    };
    for (const C of [
      typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext : null,
      typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext : null,
    ].filter(Boolean)) {
      const origAttrs = C.prototype.getContextAttributes;
      C.prototype.getContextAttributes = function () {
        return { ...origAttrs.call(this), preserveDrawingBuffer: false };
      };
    }
  });
  await spoofPage.goto(BASE + '/test-harness.html', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await spoofPage.waitForFunction(() => window.__allLoaded === true, { timeout: 60000 });
  const canaryResult = await spoofPage.evaluate(async () => {
    const host = document.createElement('div');
    host.style.cssText = 'width:320px;height:200px';
    document.body.prepend(host);
    const integrityEvents = [];
    host.addEventListener('archx-integrity', (e) => integrityEvents.push(e.detail));
    const inst = window.Archx.load.image(host, { id: 'gallery-011' }, {
      mode: 'vault', integrity: 'monitor', debug: true, lazy: false, automation: 'monitor',
    });
    await inst.ready;
    host.scrollIntoView();
    const deadline = Date.now() + 15000;
    let canary = inst._debug()?.canary;
    while (Date.now() < deadline && !canary?.preserveFlagged) {
      await new Promise((r) => setTimeout(r, 150));
      canary = inst._debug()?.canary;
    }
    const out = { loaded: inst.loaded, canary, integrityEvents };
    return out;
  });
  await spoofPage.close();
  check('readPixels canary catches preserveDrawingBuffer rewrite hidden by spoofed getContextAttributes',
    canaryResult.canary?.preserveFlagged === true &&
      canaryResult.integrityEvents.some((d) => d?.issue === 'preserveDrawingBuffer-rewritten'),
    JSON.stringify({ canaryResult, spoofErrors }));

  console.log('\n[8] Network payload — captured bytes are scrambled, master unreachable');
  const directMaster = await fetch(BASE + '/demo-masters/aurora-valley.jpg');
  check('GET master path directly -> 404', directMaster.status === 404);
  const noToken = await fetch(BASE + '/archx/i/aurora-valley');
  check('GET image route without token -> 403', noToken.status === 403);
  const token = await (await fetch(BASE + '/archx/token/aurora-valley?w=800', { method: 'POST', headers: { 'x-archx-request': 'token' } })).json();
  const payloadRes = await fetch(BASE + token.cleanUrl, { headers: { 'x-archx-token': token.token } });
  const payload = new Uint8Array(await payloadRes.arrayBuffer());
  check('payload content-type is not an image', (payloadRes.headers.get('content-type') || '').includes('octet-stream'));
  const headerLen = new DataView(payload.buffer).getUint32(6, false);
  const header = JSON.parse(new TextDecoder().decode(payload.slice(10, 10 + headerLen)));
  const inner = Buffer.from(payload.slice(10 + headerLen));
  const masterRaw = await sharp(fs.readFileSync(path.join(root, 'demo-masters/aurora-valley.jpg'))).resize(160, 90).removeAlpha().raw().toBuffer();
  const innerRaw = await sharp(inner).resize(160, 90).removeAlpha().raw().toBuffer();
  let netMad = 0; for (let i = 0; i < masterRaw.length; i++) netMad += Math.abs(masterRaw[i] - innerRaw[i]); netMad /= masterRaw.length;
  check('captured payload pixels are a scrambled mosaic vs master', netMad > 24, `mean abs diff=${netMad.toFixed(1)}`);
  check('server down-scaled master (never sends full res)', header.w === 800, `header.w=${header.w}`);
  check('demo payload carries server-baked watermark + forensic + StegoMark flags',
    header.wm === 1 && header.fx === 1 && header.sg === 1,
    JSON.stringify({ wm: header.wm, fx: header.fx, sg: header.sg }));
  const replay = await fetch(BASE + token.cleanUrl, { headers: { 'x-archx-token': token.token } });
  check('replaying the same signed token is rejected (one-time token)', replay.status === 403, `HTTP ${replay.status}`);
  const token2 = await (await fetch(BASE + '/archx/token/aurora-valley?w=800', { method: 'POST', headers: { 'user-agent': 'Browser-A', 'x-archx-request': 'token' } })).json();
  const wrongBrowser = await fetch(BASE + token2.cleanUrl, { headers: { 'user-agent': 'Browser-B', 'x-archx-token': token2.token } });
  check('signed token presented by a different browser/User-Agent is rejected', wrongBrowser.status === 403, `HTTP ${wrongBrowser.status}`);

  console.log('\n[8b] Scale delivery — precomputed manifest assets and catalog profile');
  scaleTraffic.manifests = 0;
  scaleTraffic.assetPayloads = 0;
  const scaleAssets = await page.evaluate(async () => {
    window.Archx.config({ assetManifest: '/demo/protected-test/archx-manifest.json' });
    const makeHost = (id) => {
      const host = document.createElement('div');
      host.id = id;
      host.style.cssText = 'width:340px;height:220px';
      document.body.appendChild(host);
      return host;
    };
    const aurora = window.Archx.load.image(makeHost('t-asset-aurora'), { assetId: 'aurora-valley' }, {
      ...window.Archx.preset('catalog'), lazy: false, debug: true, shadow: 'open',
    });
    const neon = window.Archx.load.image(makeHost('t-asset-neon'), { asset: 'neon-portrait' }, {
      ...window.Archx.preset('catalog'), lazy: false, debug: true, shadow: 'open',
    });
    const element = document.createElement('archx-image');
    element.id = 't-asset-element';
    element.setAttribute('asset-id', 'aurora-valley');
    element.setAttribute('asset-manifest', '/demo/protected-test/archx-manifest.json');
    element.setAttribute('preset', 'catalog');
    element.style.cssText = 'width:340px;height:220px';
    document.body.appendChild(element);
    await Promise.all([aurora.ready, neon.ready, element.ready]);
    window.__scaleInstances = [aurora, neon];
    return {
      auroraLoaded: aurora.loaded,
      neonLoaded: neon.loaded,
      auroraWidth: aurora._debug()?.meta?.origW,
      neonWidth: neon._debug()?.meta?.origW,
      catalog: window.Archx.preset('catalog'),
      buckets: window.Archx.sourceWidthBuckets,
    };
  });
  check('precomputed manifest assets render through the normal protected viewer',
    scaleAssets.auroraLoaded && scaleAssets.neonLoaded, JSON.stringify(scaleAssets));
  check('manifest responsive selection picks the 640px variant for a 340×220 cover box',
    scaleAssets.auroraWidth === 640, `aurora=${scaleAssets.auroraWidth}`);
  const assetShot = await boxStats('#t-asset-aurora');
  check('manifest asset screenshot is a real picture, not the scrambled payload',
    assetShot.std > 18 && assetShot.mean > 12, `mean=${assetShot.mean.toFixed(1)} std=${assetShot.std.toFixed(1)}`);
  const elementShot = await boxStats('#t-asset-element');
  check('<archx-image asset-id> uses the same manifest path',
    elementShot.std > 18 && elementShot.mean > 12, `mean=${elementShot.mean.toFixed(1)} std=${elementShot.std.toFixed(1)}`);
  check('one shared manifest fetch serves every asset instance',
    scaleTraffic.manifests === 1, `manifest requests=${scaleTraffic.manifests}`);
  check('catalog preset uses device-pixel sampling, buckets, HTTP cache, and batch minting',
    scaleAssets.catalog.qualityProfile === 'catalog' &&
      scaleAssets.catalog.sourceOversample === 1 &&
      scaleAssets.catalog.tokenBatch === true &&
      scaleAssets.catalog.httpCache === 'default' &&
      scaleAssets.buckets.includes(640),
    JSON.stringify(scaleAssets.catalog));
  await page.evaluate(() => {
    for (const inst of window.__scaleInstances || []) inst.destroy();
    document.querySelector('#t-asset-aurora')?.remove();
    document.querySelector('#t-asset-neon')?.remove();
    document.querySelector('#t-asset-element')?.remove();
  });

  console.log('\n[8c] Integrity pinning, network-aware sampling, and asset preload');
  const browserManifest = JSON.parse(fs.readFileSync(path.join(protectedTestDir, 'archx-manifest.json'), 'utf8'));
  const auroraVariantWidths = browserManifest.assets['aurora-valley'].variants.map((v) => v.width);
  const neonMaxWidth = Math.max(...browserManifest.assets['neon-portrait'].variants.map((v) => v.width));
  const networkBeforePreload = scaleTraffic.assetPayloadNetwork;
  const preloadOutcome = await page.evaluate(async () => {
    const result = await window.Archx.preloadAssets(['neon-portrait', 'missing-asset'], {
      ...window.Archx.preset('catalog'),
      assetManifest: '/demo/protected-test/archx-manifest.json',
      width: 960,
    });
    return {
      preloaded: [...result.preloaded],
      failed: result.failed.map((f) => f.id),
      skipped: result.skipped || null,
    };
  });
  check('preloadAssets warms the requested variant and reports unknown ids without throwing',
    preloadOutcome.preloaded.includes('neon-portrait') &&
      preloadOutcome.failed.includes('missing-asset') && preloadOutcome.skipped === null,
    JSON.stringify(preloadOutcome));
  // CDP response events can lag the in-page fetch resolution on a loaded
  // machine; wait (bounded) for the counter to settle before asserting.
  for (let i = 0; i < 80 && scaleTraffic.assetPayloadNetwork < networkBeforePreload + 1; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
  check('preloading fetches the largest variant from the network exactly once',
    scaleTraffic.assetPayloadNetwork === networkBeforePreload + 1,
    `network 200s before=${networkBeforePreload} after=${scaleTraffic.assetPayloadNetwork}`);
  const warmLoad = await page.evaluate(async () => {
    const host = document.createElement('div');
    host.id = 't-preload-warm';
    host.style.cssText = 'width:900px;height:500px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { assetId: 'neon-portrait' }, {
      ...window.Archx.preset('catalog'), lazy: false, cacheBitmap: false, debug: true, shadow: 'open',
    });
    await inst.ready;
    const out = { loaded: inst.loaded, width: inst._debug()?.meta?.origW };
    inst.destroy();
    host.remove();
    return out;
  });
  check('a preloaded variant then renders at the preloaded width',
    warmLoad.loaded && warmLoad.width === neonMaxWidth, JSON.stringify(warmLoad));
  check('the warmed variant is served from the HTTP cache, not refetched',
    scaleTraffic.assetPayloadNetwork === networkBeforePreload + 1,
    `network 200s=${scaleTraffic.assetPayloadNetwork}`);

  const integrityOutcomes = await page.evaluate(async (manifestPin) => {
    const manifestUrl = '/demo/protected-test/archx-manifest.json';
    const makeHost = (id) => {
      const host = document.createElement('div');
      host.id = id;
      host.style.cssText = 'width:340px;height:220px';
      document.body.appendChild(host);
      return host;
    };
    const attempt = (host, source, options) => new Promise((resolve) => {
      const inst = window.Archx.load.image(host, source, {
        ...window.Archx.preset('catalog'), lazy: false, debug: true, shadow: 'open',
        ...options,
        onError: (err) => resolve({ loaded: false, error: String(err?.message || err) }),
      });
      inst.ready.catch(() => {});
      const iv = setInterval(() => {
        if (inst.loaded) {
          clearInterval(iv);
          resolve({ loaded: true, width: inst._debug()?.meta?.origW });
        }
      }, 50);
      setTimeout(() => { clearInterval(iv); resolve({ loaded: inst.loaded, error: 'timeout' }); }, 20000);
      window.__integrityInstances = [...(window.__integrityInstances || []), inst];
    });

    const outcomes = {};
    outcomes.pinned = await attempt(makeHost('t-pin-ok'), { assetId: 'aurora-valley' },
      { assetManifestIntegrity: manifestPin });
    outcomes.wrongPin = await attempt(makeHost('t-pin-bad'), { assetId: 'aurora-valley' },
      { assetManifestIntegrity: 'sha256-' + '0'.repeat(64) });

    const originalConnection = navigator.connection;
    const setConnection = (value) => Object.defineProperty(navigator, 'connection',
      { configurable: true, value });
    try {
      outcomes.full = await attempt(makeHost('t-net-full'), { assetId: 'aurora-valley' },
        { sourceOversample: 2, cacheBitmap: false });
      setConnection({ saveData: true, effectiveType: '2g' });
      outcomes.constrained = await attempt(makeHost('t-net-slow'), { assetId: 'aurora-valley' },
        { sourceOversample: 2, cacheBitmap: false });
      const skipped = await window.Archx.preloadAssets(['aurora-valley'], {
        assetManifest: manifestUrl, networkAware: true,
      });
      outcomes.preloadSkipped = skipped.skipped || null;
    } finally {
      setConnection(originalConnection);
    }

    for (const inst of window.__integrityInstances || []) inst.destroy();
    for (const id of ['t-pin-ok', 't-pin-bad', 't-net-full', 't-net-slow']) {
      document.querySelector('#' + id)?.remove();
    }
    return outcomes;
  }, 'sha256-' + browserCatalogBuild.manifestSha256);
  check('a correct manifest integrity pin loads normally',
    integrityOutcomes.pinned.loaded === true, JSON.stringify(integrityOutcomes.pinned));
  check('a wrong manifest integrity pin is rejected before any key or variant is trusted',
    integrityOutcomes.wrongPin.loaded === false && /integrity/.test(integrityOutcomes.wrongPin.error || ''),
    JSON.stringify(integrityOutcomes.wrongPin));
  check('network-aware sampling serves a smaller derivative on Save-Data/2g',
    integrityOutcomes.full.width === auroraVariantWidths.at(-1) &&
      integrityOutcomes.constrained.width === auroraVariantWidths[1],
    JSON.stringify({ full: integrityOutcomes.full, constrained: integrityOutcomes.constrained }));
  check('preloadAssets refuses to spend data on Save-Data connections',
    integrityOutcomes.preloadSkipped === 'save-data', JSON.stringify(integrityOutcomes));

  const tamperVariant = browserManifest.assets['aurora-valley'].variants.find((v) => v.width === 640);
  const tamperPath = path.join(protectedTestDir, decodeURIComponent(path.basename(tamperVariant.url)));
  const tamperOriginal = fs.readFileSync(tamperPath);
  const tamperBytes = Buffer.from(tamperOriginal);
  tamperBytes[tamperBytes.length - 1] ^= 0xff;
  fs.writeFileSync(tamperPath, tamperBytes);
  let tamperOutcome;
  try {
    tamperOutcome = await page.evaluate(async () => {
      const host = document.createElement('div');
      host.id = 't-tampered';
      host.style.cssText = 'width:340px;height:220px';
      document.body.appendChild(host);
      const outcome = await new Promise((resolve) => {
        const inst = window.Archx.load.image(host, { assetId: 'aurora-valley' }, {
          ...window.Archx.preset('catalog'), lazy: false, debug: true, shadow: 'open',
          cacheBitmap: false, cachePayload: false, assetHttpCache: 'no-store',
          onError: (err) => resolve({ loaded: false, error: String(err?.message || err) }),
        });
        inst.ready.catch(() => {});
        const iv = setInterval(() => {
          if (inst.loaded) { clearInterval(iv); resolve({ loaded: true }); }
        }, 50);
        setTimeout(() => { clearInterval(iv); resolve({ loaded: inst.loaded, error: 'timeout' }); }, 20000);
        window.__tamperInstance = inst;
      });
      window.__tamperInstance?.destroy();
      host.remove();
      return outcome;
    });
  } finally {
    fs.writeFileSync(tamperPath, tamperOriginal);
  }
  check('a tampered CDN variant fails its manifest SHA-256 check and never renders',
    tamperOutcome.loaded === false && /integrity/.test(tamperOutcome.error || ''),
    JSON.stringify(tamperOutcome));

  console.log('\n[8d] Scattered-memory display — origin-tainted readback and pixel-exact quality');
  // The page origin is 127.0.0.1; the same server reached as "localhost" is
  // a different origin, which is exactly what tainting needs.
  const taintOutcome = await page.evaluate(async (taintUrl) => {
    // Warm the immutable HTTP cache so the client's bounded first-paint wait
    // for the pixel is a cache hit even on a loaded test machine.
    await new Promise((res) => {
      const i = new Image();
      i.onload = i.onerror = () => res();
      i.src = taintUrl;
    });
    const host = document.createElement('div');
    host.id = 't-tainted';
    host.style.cssText = 'width:320px;height:240px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'aurora-valley' }, {
      mode: 'shield', lazy: false, debug: true, shadow: 'open', taintUrl,
    });
    await inst.ready;
    const canvas = inst._debug().canvas;
    const out = { loaded: inst.loaded };
    try { HTMLCanvasElement.prototype.toDataURL.call(canvas, 'image/png'); out.prototypeDataUrl = 'returned'; }
    catch (e) { out.prototypeDataUrl = e.name; }
    try {
      CanvasRenderingContext2D.prototype.getImageData.call(canvas.getContext('2d'), 0, 0, 1, 1);
      out.prototypePixels = 'returned';
    } catch (e) { out.prototypePixels = e.name; }
    try { out.instanceDataUrl = typeof canvas.toDataURL('image/png') === 'string'; }
    catch { out.instanceDataUrl = false; }
    window.__taintInstance = inst;
    return out;
  }, `http://localhost:${PORT}/archx/taint.png`);
  check('origin-tainted shield canvas: even prototype-call toDataURL throws SecurityError',
    taintOutcome.loaded && taintOutcome.prototypeDataUrl === 'SecurityError',
    JSON.stringify(taintOutcome));
  check('origin-tainted shield canvas: even prototype-call getImageData throws SecurityError',
    taintOutcome.prototypePixels === 'SecurityError', JSON.stringify(taintOutcome));
  check('instance-level decoy readback still answers on a tainted canvas (friendly layer intact)',
    taintOutcome.instanceDataUrl === true, JSON.stringify(taintOutcome));
  const taintedShot = await boxStats('#t-tainted');
  check('tainting does not change the displayed picture',
    taintedShot.std > 18 && taintedShot.mean > 12,
    `mean=${taintedShot.mean.toFixed(1)} std=${taintedShot.std.toFixed(1)}`);
  await page.evaluate(() => {
    window.__taintInstance?.destroy();
    document.querySelector('#t-tainted')?.remove();
  });

  const vaultShadow = await page.evaluate(() => {
    const canvas = window.__instances.vault._debug().canvas;
    return {
      stream: Object.prototype.hasOwnProperty.call(canvas, 'captureStream'),
      dataUrl: Object.prototype.hasOwnProperty.call(canvas, 'toDataURL'),
      blob: Object.prototype.hasOwnProperty.call(canvas, 'toBlob'),
    };
  });
  check('WebGL vault canvas shadows record/read APIs like 2D canvases (no live captureStream of animated frames)',
    vaultShadow.stream && vaultShadow.dataUrl && vaultShadow.blob, JSON.stringify(vaultShadow));

  // Pixel-exactness: the shield display must equal the authorized derivative
  // pixel-for-pixel at 1:1 — zero quality loss beyond the derivative itself.
  let exactToken = null;
  let exactPayload = null;
  const exactLoad = await page.evaluate(async () => {
    const host = document.createElement('div');
    host.id = 't-exact';
    host.style.cssText = 'width:320px;height:240px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'aurora-valley' }, {
      mode: 'shield', lazy: false, debug: true, shadow: 'open',
      sourceOversample: 1, dprCap: 1, forensic: false,
    });
    await inst.ready;
    const out = {
      loaded: inst.loaded,
      origW: inst._debug()?.meta?.origW,
      origH: inst._debug()?.meta?.origH,
    };
    window.__exactInstance = inst;
    return out;
  });
  // Deterministic replay instead of CDP response-body sniffing (whose
  // bodies can be evicted under the 100-image gallery's network pressure):
  // a derivative is a pure function of (id, box, quality, grid, key), so
  // minting the same cover box the browser reported returns the same
  // derivative it painted.
  if (exactLoad.loaded && exactLoad.origW && exactLoad.origH) {
    try {
      exactToken = await (await fetch(
        `${BASE}/archx/token/aurora-valley?w=${exactLoad.origW}&bw=${exactLoad.origW}&bh=${exactLoad.origH}&fit=cover`,
        { method: 'POST', headers: { 'x-archx-request': 'token' } })).json();
      exactPayload = Buffer.from(await (await fetch(BASE + exactToken.cleanUrl,
        { headers: { 'x-archx-token': exactToken.token } })).arrayBuffer());
    } catch {}
  }
  let exactDiff = null;
  if (exactLoad.loaded && exactToken && exactPayload) {
    const decoded = decodeContainer(new Uint8Array(exactPayload));
    const restored = await unscrambleImage(Buffer.from(decoded.payload), {
      grid: decoded.header.grid, key: exactToken.key,
      w: decoded.header.w, h: decoded.header.h,
    });
    const refMeta = await sharp(restored).metadata();
    const targetAspect = 320 / 240;
    let refPipeline = sharp(restored);
    if (refMeta.width / refMeta.height > targetAspect) {
      const cw = Math.round(refMeta.height * targetAspect);
      refPipeline = refPipeline.extract({
        left: Math.round((refMeta.width - cw) / 2), top: 0, width: cw, height: refMeta.height,
      });
      if (cw !== 320) refPipeline = refPipeline.resize(320, 240);
    } else if (refMeta.width !== 320 || refMeta.height !== 240) {
      refPipeline = refPipeline.resize(320, 240, { fit: 'cover' });
    }
    const refRaw = (await refPipeline.removeAlpha().raw().toBuffer({ resolveWithObject: true })).data;
    const exactEl = await page.$('#t-exact');
    const shotRaw = (await sharp(await exactEl.screenshot()).removeAlpha().raw()
      .toBuffer({ resolveWithObject: true })).data;
    let absSum = 0;
    let within2 = 0;
    const px = Math.min(refRaw.length, shotRaw.length) / 3;
    for (let i = 0; i < px; i++) {
      const d = Math.max(
        Math.abs(refRaw[i * 3] - shotRaw[i * 3]),
        Math.abs(refRaw[i * 3 + 1] - shotRaw[i * 3 + 1]),
        Math.abs(refRaw[i * 3 + 2] - shotRaw[i * 3 + 2]),
      );
      absSum += d;
      if (d <= 2) within2++;
    }
    exactDiff = { mad: absSum / px, within2: within2 / px, refW: refMeta.width, refH: refMeta.height };
  }
  check('shield display is pixel-exact against the authorized derivative at 1:1 (no added quality loss)',
    !!exactDiff && exactDiff.mad < 2 && exactDiff.within2 > 0.99,
    JSON.stringify({ exactLoad, exactDiff, replayOk: !!(exactToken && exactPayload) }));
  await page.evaluate(() => {
    window.__exactInstance?.destroy();
    document.querySelector('#t-exact')?.remove();
  });

  console.log('\n[8e] Scramble plan v2 — the browser applies the 128-bit-seed plan from the header');
  {
    const v2Manifest = JSON.parse(fs.readFileSync(path.join(protectedTestDirV2, 'archx-manifest.json'), 'utf8'));
    const v2Variant = v2Manifest.assets['aurora-valley'].variants[0];
    const v2Bytes = fs.readFileSync(path.join(protectedTestDirV2, path.basename(new URL(v2Variant.url, 'http://local').pathname)));
    const v2Decoded = decodeContainer(new Uint8Array(v2Bytes));
    check('plan v2 catalog asset declares pv=2 in its container header',
      v2Decoded.header.pv === 2, JSON.stringify(v2Decoded.header));
    const v2Load = await page.evaluate(async () => {
      const host = document.createElement('div');
      host.id = 't-planv2';
      host.style.cssText = 'width:320px;height:240px';
      document.body.appendChild(host);
      const inst = window.Archx.load.image(host, { assetId: 'aurora-valley' }, {
        assetManifest: '/demo/protected-test-v2/archx-manifest.json',
        assetHttpCache: 'no-store',
        mode: 'shield', lazy: false, debug: true, shadow: 'open',
        sourceOversample: 1, dprCap: 1,
      });
      await inst.ready;
      const out = { loaded: inst.loaded, planVersion: inst._debug()?.meta?.plan?.version ?? null };
      window.__planV2Instance = inst;
      return out;
    });
    const madAgainst = async (planVersion) => {
      const restored = await unscrambleImage(Buffer.from(v2Decoded.payload), {
        grid: v2Decoded.header.grid, key: v2Manifest.assets['aurora-valley'].key,
        w: v2Decoded.header.w, h: v2Decoded.header.h, planVersion,
      });
      const refRaw = (await sharp(restored).resize(320, 240, { fit: 'cover' }).removeAlpha()
        .raw().toBuffer({ resolveWithObject: true })).data;
      const el = await page.$('#t-planv2');
      const shotRaw = (await sharp(await el.screenshot()).removeAlpha().raw()
        .toBuffer({ resolveWithObject: true })).data;
      let sum = 0;
      for (let i = 0; i < refRaw.length; i++) sum += Math.abs(refRaw[i] - shotRaw[i]);
      return sum / refRaw.length;
    };
    const madV2 = v2Load.loaded ? await madAgainst(2) : Infinity;
    const madV1 = v2Load.loaded ? await madAgainst(1) : 0;
    // Threshold is loose because the reference's cover crop and the
    // browser's cover math differ slightly at the edges; the plan signal is
    // the 10x gap to the v1 reference below (MAD ~57).
    check('browser unscrambles the v2 payload with the v2 plan (display matches the v2 reference)',
      v2Load.loaded && v2Load.planVersion === 2 && madV2 < 12,
      JSON.stringify({ v2Load, madV2: Number(madV2.toFixed(2)) }));
    check('the legacy v1 plan does NOT reconstruct what the browser shows',
      madV1 > 20, `madV1=${madV1.toFixed(1)}`);
    await page.evaluate(() => {
      window.__planV2Instance?.destroy();
      document.querySelector('#t-planv2')?.remove();
    });
  }

  console.log('\n[9] Performance — 100-image protected gallery');
  scaleTraffic.batchMints = 0;
  scaleTraffic.singleMints = 0;
  const gallery = await page.evaluate(() => window.__loadGallery(100));
  const galleryDom = await page.evaluate(() => ({
    imgs: document.querySelectorAll('#gallery img').length,
    loaded: window.__galleryInstances.filter((i) => i.loaded).length,
  }));
  check('100 gallery images all loaded', galleryDom.loaded === 100, `${galleryDom.loaded}/100 in ${(gallery.ms / 1000).toFixed(1)}s`);
  check('100 gallery images created 0 <img> tags', galleryDom.imgs === 0);
  check('gallery load completes within a sane budget (<90s in headless CI, ~seconds in a real browser)', gallery.ms < 90000, `${(gallery.ms / 1000).toFixed(1)}s`);
  check('100-image gallery coalesces token mints instead of issuing 100 mint requests',
    scaleTraffic.batchMints > 0 && scaleTraffic.batchMints <= 25 && scaleTraffic.singleMints === 0,
    `batch=${scaleTraffic.batchMints} single=${scaleTraffic.singleMints}`);

  check('no page errors during the whole run', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));
} catch (err) {
  failures++;
  console.error('\n✘ Browser test crashed:', err);
} finally {
  await browser.close().catch(() => {});
  server.kill('SIGTERM');
  fs.rmSync(protectedTestDir, { recursive: true, force: true });
  fs.rmSync(protectedTestDirV2, { recursive: true, force: true });
}

console.log(`\n${failures === 0 ? '🟢 ALL BROWSER CHECKS PASSED' : '🔴 FAILURES: ' + failures}  (${checks} checks)`);
process.exit(failures ? 1 : 0);
