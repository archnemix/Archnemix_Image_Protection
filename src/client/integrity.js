/**
 * Hook/automation tripwires: native-function audits, early-load snapshots, headless signals. Reports only — policy (monitor/lock) lives in the viewer.
 */
import { NATIVES, isNativeFn } from './native.js';

export const AUDIT_WEBGL_METHODS = [
  'texImage2D', 'readPixels', 'drawArrays', 'drawElements',
  'createTexture', 'bindTexture', 'bindFramebuffer', 'createFramebuffer',
  'framebufferTexture2D', 'createShader', 'shaderSource', 'compileShader',
  'createProgram', 'linkProgram', 'useProgram', 'getContextAttributes',
  'uniform1f', 'uniform2f', 'uniform1i', 'viewport', 'activeTexture',
  'texParameteri', 'pixelStorei', 'generateMipmap', 'getUniformLocation',
  'attachShader', 'getShaderParameter', 'getProgramParameter', 'createBuffer',
  'bindBuffer', 'bufferData', 'enableVertexAttribArray', 'vertexAttribPointer',
  'getExtension',
];
// The reader PROTOTYPE object is identity-stable, so probe it once and
// re-read `.read` off it per audit (still detects later replacement)
// instead of allocating a stream + locked reader on every call.
export let readerProtoCache;
export function currentReaderRead() {
  try {
    if (readerProtoCache === undefined) {
      readerProtoCache = Object.getPrototypeOf(new ReadableStream().getReader());
    }
    return readerProtoCache?.read ?? null;
  } catch { return null; }
}

/** Names of sensitive APIs that look hooked (replaced or non-native). */
export function currentDescriptorAccessor(ctorName, prop, kind) {
  try {
    const ctor = ctorName === 'HTMLCanvasElement'
      ? (typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement : null)
      : (typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D : null);
    if (!ctor) return null;
    return Object.getOwnPropertyDescriptor(ctor.prototype, prop)?.[kind] || null;
  } catch { return null; }
}

export function auditIntegrity() {
  const g = globalThis;
  const current = [
    ['fetch', g.fetch, NATIVES.fetch],
    ['createImageBitmap', g.createImageBitmap, NATIVES.createImageBitmap],
    ['URL.createObjectURL', typeof URL !== 'undefined' ? URL.createObjectURL : null, NATIVES.createObjectURL],
    ['HTMLCanvasElement.prototype.getContext', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.getContext : null, NATIVES.canvasGetContext],
    ['HTMLCanvasElement.prototype.toDataURL', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.toDataURL : null, NATIVES.canvasToDataURL],
    ['HTMLCanvasElement.prototype.toBlob', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.toBlob : null, NATIVES.canvasToBlob],
    ['CanvasRenderingContext2D.prototype.drawImage', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.drawImage : null, NATIVES.ctxDrawImage],
    ['CanvasRenderingContext2D.prototype.getImageData', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.getImageData : null, NATIVES.ctxGetImageData],
    ['CanvasRenderingContext2D.prototype.putImageData', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.putImageData : null, NATIVES.ctxPutImageData],
    ['CanvasRenderingContext2D.prototype.save', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.save : null, NATIVES.ctxSave],
    ['CanvasRenderingContext2D.prototype.restore', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.restore : null, NATIVES.ctxRestore],
    ['CanvasRenderingContext2D.prototype.translate', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.translate : null, NATIVES.ctxTranslate],
    ['CanvasRenderingContext2D.prototype.scale', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.scale : null, NATIVES.ctxScale],
    ['CanvasRenderingContext2D.prototype.rotate', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.rotate : null, NATIVES.ctxRotate],
    ['CanvasRenderingContext2D.prototype.setTransform', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.setTransform : null, NATIVES.ctxSetTransform],
    ['Function.prototype.call', Function.prototype.call, NATIVES.fnCall],
    ['Function.prototype.apply', Function.prototype.apply, NATIVES.fnApply],
    ['Function.prototype.bind', Function.prototype.bind, NATIVES.fnBind],
    ['Function.prototype.toString', Function.prototype.toString, NATIVES.fnToString],
    ['Reflect.apply', typeof Reflect !== 'undefined' ? Reflect.apply : null, NATIVES.reflectApply],
    ['HTMLCanvasElement.prototype.width.get', currentDescriptorAccessor('HTMLCanvasElement', 'width', 'get'), NATIVES.canvasWidthGet],
    ['HTMLCanvasElement.prototype.width.set', currentDescriptorAccessor('HTMLCanvasElement', 'width', 'set'), NATIVES.canvasWidthSet],
    ['HTMLCanvasElement.prototype.height.get', currentDescriptorAccessor('HTMLCanvasElement', 'height', 'get'), NATIVES.canvasHeightGet],
    ['HTMLCanvasElement.prototype.height.set', currentDescriptorAccessor('HTMLCanvasElement', 'height', 'set'), NATIVES.canvasHeightSet],
    ['CanvasRenderingContext2D.prototype.imageSmoothingQuality.get', currentDescriptorAccessor('CanvasRenderingContext2D', 'imageSmoothingQuality', 'get'), NATIVES.smoothingQualityGet],
    ['CanvasRenderingContext2D.prototype.imageSmoothingQuality.set', currentDescriptorAccessor('CanvasRenderingContext2D', 'imageSmoothingQuality', 'set'), NATIVES.smoothingQualitySet],
    ['Document.prototype.createElement', typeof Document !== 'undefined' ? Document.prototype.createElement : null, NATIVES.docCreateElement],
    ['JSON.parse', typeof JSON !== 'undefined' ? JSON.parse : null, NATIVES.jsonParse],
    ['Element.prototype.attachShadow', typeof Element !== 'undefined' ? Element.prototype.attachShadow : null, NATIVES.attachShadow],
    ['ReadableStream.prototype.getReader', typeof ReadableStream !== 'undefined' ? ReadableStream.prototype.getReader : null, NATIVES.streamGetReader],
    ['ReadableStreamDefaultReader.prototype.read', currentReaderRead(), NATIVES.streamReaderRead],
    ['Response.prototype.text', typeof Response !== 'undefined' ? Response.prototype.text : null, NATIVES.responseText],
    ['TextDecoder.prototype.decode', typeof TextDecoder !== 'undefined' ? TextDecoder.prototype.decode : null, NATIVES.textDecode],
    ['TextEncoder.prototype.encode', typeof TextEncoder !== 'undefined' ? TextEncoder.prototype.encode : null, NATIVES.textEncode],
    ['SubtleCrypto.prototype.importKey', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).importKey : null, NATIVES.subtleImportKey],
    ['SubtleCrypto.prototype.decrypt', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).decrypt : null, NATIVES.subtleDecrypt],
    ['SubtleCrypto.prototype.encrypt', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).encrypt : null, NATIVES.subtleEncrypt],
    ['SubtleCrypto.prototype.digest', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).digest : null, NATIVES.subtleDigest],
    ['SubtleCrypto.prototype.sign', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).sign : null, NATIVES.subtleSign],
    ['SubtleCrypto.prototype.generateKey', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).generateKey : null, NATIVES.subtleGenerateKey],
    ['SubtleCrypto.prototype.exportKey', NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).exportKey : null, NATIVES.subtleExportKey],
    ['Crypto.prototype.getRandomValues', (() => { try { return globalThis.crypto?.getRandomValues || null; } catch { return null; } })(), NATIVES.getRandomValues],
  ];
  for (const [label, ctor, capturedMap] of [
    ['WebGLRenderingContext', typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext : null, NATIVES.webgl1],
    ['WebGL2RenderingContext', typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext : null, NATIVES.webgl2],
  ]) {
    for (const method of AUDIT_WEBGL_METHODS) {
      current.push([
        `${label}.prototype.${method}`,
        ctor ? ctor.prototype[method] : null,
        capturedMap?.[method] ?? null,
      ]);
    }
  }
  const issues = [];
  for (const [name, now, captured] of current) {
    if (!captured && !now) continue; // API absent in this environment
    if (now !== captured || (captured && !isNativeFn(captured))) issues.push(name);
  }
  return issues;
}

/**
 * Detailed integrity report. `issues` is the backwards-compatible name list;
 * `capturedNonNative` identifies functions that already looked replaced when
 * this module was evaluated (an early userscript/extension may have run),
 * while `changedSinceLoad` identifies later replacement. A clean report is
 * not proof of an unhooked browser: native-looking proxies, browser/CDP-level
 * capture, compromised extensions, and modified browsers can evade it.
 */
export function auditIntegrityDetails() {
  const issues = auditIntegrity();
  const capturedByName = new Map([
    ['fetch', NATIVES.fetch],
    ['createImageBitmap', NATIVES.createImageBitmap],
    ['URL.createObjectURL', NATIVES.createObjectURL],
    ['HTMLCanvasElement.prototype.getContext', NATIVES.canvasGetContext],
    ['HTMLCanvasElement.prototype.toDataURL', NATIVES.canvasToDataURL],
    ['HTMLCanvasElement.prototype.toBlob', NATIVES.canvasToBlob],
    ['CanvasRenderingContext2D.prototype.drawImage', NATIVES.ctxDrawImage],
    ['CanvasRenderingContext2D.prototype.getImageData', NATIVES.ctxGetImageData],
    ['CanvasRenderingContext2D.prototype.putImageData', NATIVES.ctxPutImageData],
    ['CanvasRenderingContext2D.prototype.save', NATIVES.ctxSave],
    ['CanvasRenderingContext2D.prototype.restore', NATIVES.ctxRestore],
    ['CanvasRenderingContext2D.prototype.translate', NATIVES.ctxTranslate],
    ['CanvasRenderingContext2D.prototype.scale', NATIVES.ctxScale],
    ['CanvasRenderingContext2D.prototype.rotate', NATIVES.ctxRotate],
    ['CanvasRenderingContext2D.prototype.setTransform', NATIVES.ctxSetTransform],
    ['Function.prototype.call', NATIVES.fnCall],
    ['Function.prototype.apply', NATIVES.fnApply],
    ['Function.prototype.bind', NATIVES.fnBind],
    ['Function.prototype.toString', NATIVES.fnToString],
    ['Reflect.apply', NATIVES.reflectApply],
    ['HTMLCanvasElement.prototype.width.get', NATIVES.canvasWidthGet],
    ['HTMLCanvasElement.prototype.width.set', NATIVES.canvasWidthSet],
    ['HTMLCanvasElement.prototype.height.get', NATIVES.canvasHeightGet],
    ['HTMLCanvasElement.prototype.height.set', NATIVES.canvasHeightSet],
    ['CanvasRenderingContext2D.prototype.imageSmoothingQuality.get', NATIVES.smoothingQualityGet],
    ['CanvasRenderingContext2D.prototype.imageSmoothingQuality.set', NATIVES.smoothingQualitySet],
    ['Document.prototype.createElement', NATIVES.docCreateElement],
    ['JSON.parse', NATIVES.jsonParse],
    ['Element.prototype.attachShadow', NATIVES.attachShadow],
    ['ReadableStream.prototype.getReader', NATIVES.streamGetReader],
    ['ReadableStreamDefaultReader.prototype.read', NATIVES.streamReaderRead],
    ['Response.prototype.text', NATIVES.responseText],
    ['TextDecoder.prototype.decode', NATIVES.textDecode],
    ['TextEncoder.prototype.encode', NATIVES.textEncode],
    ['SubtleCrypto.prototype.importKey', NATIVES.subtleImportKey],
    ['SubtleCrypto.prototype.decrypt', NATIVES.subtleDecrypt],
    ['SubtleCrypto.prototype.encrypt', NATIVES.subtleEncrypt],
    ['SubtleCrypto.prototype.digest', NATIVES.subtleDigest],
    ['SubtleCrypto.prototype.sign', NATIVES.subtleSign],
    ['SubtleCrypto.prototype.generateKey', NATIVES.subtleGenerateKey],
    ['SubtleCrypto.prototype.exportKey', NATIVES.subtleExportKey],
    ['Crypto.prototype.getRandomValues', NATIVES.getRandomValues],
  ]);
  for (const [label, capturedMap] of [
    ['WebGLRenderingContext', NATIVES.webgl1],
    ['WebGL2RenderingContext', NATIVES.webgl2],
  ]) {
    for (const [method, fn] of Object.entries(capturedMap || {})) {
      capturedByName.set(`${label}.prototype.${method}`, fn);
    }
  }
  const capturedNonNative = issues.filter((name) => {
    const captured = capturedByName.get(name);
    return !!captured && !isNativeFn(captured);
  });
  return Object.freeze({
    ok: issues.length === 0,
    issues: Object.freeze(issues),
    capturedNonNative: Object.freeze(capturedNonNative),
    changedSinceLoad: Object.freeze(issues.filter((name) => !capturedNonNative.includes(name))),
    checked: Object.freeze([
      'fetch',
      'createImageBitmap',
      'URL.createObjectURL',
      'canvas context/readback',
      'CanvasRenderingContext2D draw/readback',
      'Document.createElement',
      'WebGL/WebGL2 texture, framebuffer, shader/program, draw, and readback methods',
    ]),
    note: 'Tripwire only: a clean result does not prove the absence of pre-load, native-looking, extension, CDP, or modified-browser hooks.',
  });
}

/**
 * Early-load snapshot for applications that can place a tiny trusted inline
 * or same-origin bootstrap before third-party scripts. Call as early as
 * possible, keep the returned opaque snapshot in a closure, and compare with
 * verifyEarlyIntegritySnapshot() after Archx loads. This narrows—but cannot
 * eliminate—the race with userscripts/extensions that run before page code.
 */
export function captureEarlyIntegritySnapshot() {
  const snapshot = Object.freeze({
    fetch: globalThis.fetch || null,
    createImageBitmap: globalThis.createImageBitmap || null,
    canvasGetContext: typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.getContext : null,
    webglDrawArrays: typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype.drawArrays : null,
    webgl2DrawArrays: typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.drawArrays : null,
    webglReadPixels: typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype.readPixels : null,
    webgl2ReadPixels: typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.readPixels : null,
    fnCall: Function.prototype.call,
    fnApply: Function.prototype.apply,
    fnBind: Function.prototype.bind,
    reflectApply: typeof Reflect !== 'undefined' ? Reflect.apply : null,
    ctxSave: typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.save : null,
    ctxRestore: typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.restore : null,
    canvasWidthSet: (() => { try { return Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, 'width')?.set || null; } catch { return null; } })(),
    canvasHeightSet: (() => { try { return Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, 'height')?.set || null; } catch { return null; } })(),
    at: Date.now(),
  });
  return snapshot;
}

export function verifyEarlyIntegritySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return Object.freeze({ ok: false, issues: Object.freeze(['missing-snapshot']) });
  const checks = [
    ['fetch', globalThis.fetch || null, snapshot.fetch],
    ['createImageBitmap', globalThis.createImageBitmap || null, snapshot.createImageBitmap],
    ['HTMLCanvasElement.prototype.getContext', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.getContext : null, snapshot.canvasGetContext],
    ['WebGLRenderingContext.prototype.drawArrays', typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype.drawArrays : null, snapshot.webglDrawArrays],
    ['WebGL2RenderingContext.prototype.drawArrays', typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.drawArrays : null, snapshot.webgl2DrawArrays],
    ['WebGLRenderingContext.prototype.readPixels', typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype.readPixels : null, snapshot.webglReadPixels],
    ['WebGL2RenderingContext.prototype.readPixels', typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.readPixels : null, snapshot.webgl2ReadPixels],
    ['Function.prototype.call', Function.prototype.call, snapshot.fnCall],
    ['Function.prototype.apply', Function.prototype.apply, snapshot.fnApply],
    ['Function.prototype.bind', Function.prototype.bind, snapshot.fnBind],
    ['Reflect.apply', typeof Reflect !== 'undefined' ? Reflect.apply : null, snapshot.reflectApply],
    ['CanvasRenderingContext2D.prototype.save', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.save : null, snapshot.ctxSave],
    ['CanvasRenderingContext2D.prototype.restore', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.restore : null, snapshot.ctxRestore],
    ['HTMLCanvasElement.prototype.width.set', currentDescriptorAccessor('HTMLCanvasElement', 'width', 'set'), snapshot.canvasWidthSet],
    ['HTMLCanvasElement.prototype.height.set', currentDescriptorAccessor('HTMLCanvasElement', 'height', 'set'), snapshot.canvasHeightSet],
  ];
  const issues = checks.filter(([, now, before]) => (before || now) && now !== before).map(([name]) => name);
  return Object.freeze({ ok: issues.length === 0, issues: Object.freeze(issues), snapshotAt: snapshot.at || null });
}

/** Cheap automation signals (headless/bot browsers). Spoofable — a tripwire. */
export function detectAutomation() {
  const signals = [];
  try {
    if (typeof navigator !== 'undefined') {
      if (navigator.webdriver) signals.push('webdriver');
      if (/HeadlessChrome|PhantomJS|Headless/i.test(navigator.userAgent || '')) signals.push('headless-ua');
      if (navigator.languages && navigator.languages.length === 0) signals.push('no-languages');
    }
    if (typeof window !== 'undefined' && window.outerWidth === 0 && window.outerHeight === 0) signals.push('zero-outer-size');
  } catch {}
  return signals;
}
