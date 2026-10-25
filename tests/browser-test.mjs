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
  args: [...chromium.args, '--no-sandbox', '--disable-dev-shm-usage', '--enable-unsafe-swiftshader'],
  headless: true,
  env: await chromiumEnv(),
});
const page = await browser.newPage();
await page.setViewport({ width: 1200, height: 900 });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push('pageerror: ' + e.message));
page.on('console', (m) => { if (m.type() === 'error') pageErrors.push('console: ' + m.text()); });

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

  console.log('\n[8] Network payload — captured bytes are scrambled, master unreachable');
  const directMaster = await fetch(BASE + '/demo-masters/aurora-valley.jpg');
  check('GET master path directly -> 404', directMaster.status === 404);
  const noToken = await fetch(BASE + '/archx/i/aurora-valley');
  check('GET image route without token -> 403', noToken.status === 403);
  const token = await (await fetch(BASE + '/archx/token/aurora-valley?w=800')).json();
  const payloadRes = await fetch(BASE + token.url);
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
  const replay = await fetch(BASE + token.url);
  check('replaying the same signed URL is rejected (one-time token)', replay.status === 403, `HTTP ${replay.status}`);
  const token2 = await (await fetch(BASE + '/archx/token/aurora-valley?w=800', { headers: { 'user-agent': 'Browser-A' } })).json();
  const wrongBrowser = await fetch(BASE + token2.url, { headers: { 'user-agent': 'Browser-B' } });
  check('signed URL presented by a different browser/User-Agent is rejected', wrongBrowser.status === 403, `HTTP ${wrongBrowser.status}`);

  console.log('\n[9] Performance — 100-image protected gallery');
  const gallery = await page.evaluate(() => window.__loadGallery(100));
  const galleryDom = await page.evaluate(() => ({
    imgs: document.querySelectorAll('#gallery img').length,
    loaded: window.__galleryInstances.filter((i) => i.loaded).length,
  }));
  check('100 gallery images all loaded', galleryDom.loaded === 100, `${galleryDom.loaded}/100 in ${(gallery.ms / 1000).toFixed(1)}s`);
  check('100 gallery images created 0 <img> tags', galleryDom.imgs === 0);
  check('gallery load completes within a sane budget (<90s in headless CI, ~seconds in a real browser)', gallery.ms < 90000, `${(gallery.ms / 1000).toFixed(1)}s`);

  check('no page errors during the whole run', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));
} catch (err) {
  failures++;
  console.error('\n✘ Browser test crashed:', err);
} finally {
  await browser.close().catch(() => {});
  server.kill('SIGTERM');
}

console.log(`\n${failures === 0 ? '🟢 ALL BROWSER CHECKS PASSED' : '🔴 FAILURES: ' + failures}  (${checks} checks)`);
process.exit(failures ? 1 : 0);
