/**
 * Pristine native references captured at module load (before any page script can hook them) + captured-dispatch wrappers. THE anti-hook foundation: everything sensitive routes through here.
 */
import { useJsonParser, useWebCrypto } from '../scramble.js';

export const NATIVES = (() => {
  const g = globalThis;
  const grab = (obj, name) => {
    try { return obj && typeof obj[name] === 'function' ? obj[name] : null; } catch { return null; }
  };
  const canvasProto = typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype : null;
  const ctx2dProto = typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype : null;
  const docProto = typeof Document !== 'undefined' ? Document.prototype : null;
  const gl1Proto = typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext.prototype : null;
  const gl2Proto = typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype : null;
  const glMethods = {
    texImage2D: grab(gl2Proto, 'texImage2D') || grab(gl1Proto, 'texImage2D'),
    readPixels: grab(gl2Proto, 'readPixels') || grab(gl1Proto, 'readPixels'),
    drawArrays: grab(gl2Proto, 'drawArrays') || grab(gl1Proto, 'drawArrays'),
    drawElements: grab(gl2Proto, 'drawElements') || grab(gl1Proto, 'drawElements'),
    createTexture: grab(gl2Proto, 'createTexture') || grab(gl1Proto, 'createTexture'),
    bindTexture: grab(gl2Proto, 'bindTexture') || grab(gl1Proto, 'bindTexture'),
    bindFramebuffer: grab(gl2Proto, 'bindFramebuffer') || grab(gl1Proto, 'bindFramebuffer'),
    createFramebuffer: grab(gl2Proto, 'createFramebuffer') || grab(gl1Proto, 'createFramebuffer'),
    framebufferTexture2D: grab(gl2Proto, 'framebufferTexture2D') || grab(gl1Proto, 'framebufferTexture2D'),
    createShader: grab(gl2Proto, 'createShader') || grab(gl1Proto, 'createShader'),
    shaderSource: grab(gl2Proto, 'shaderSource') || grab(gl1Proto, 'shaderSource'),
    compileShader: grab(gl2Proto, 'compileShader') || grab(gl1Proto, 'compileShader'),
    createProgram: grab(gl2Proto, 'createProgram') || grab(gl1Proto, 'createProgram'),
    linkProgram: grab(gl2Proto, 'linkProgram') || grab(gl1Proto, 'linkProgram'),
    useProgram: grab(gl2Proto, 'useProgram') || grab(gl1Proto, 'useProgram'),
    getContextAttributes: grab(gl2Proto, 'getContextAttributes') || grab(gl1Proto, 'getContextAttributes'),
    // Uniform setters + draw-setup (red-team C1): these were called
    // directly, so a post-load prototype hook on uniform1f could
    // silently zero the temporal/lens modulation mid-draw and
    // microtask-read a clean frame. All render-path GL calls now go
    // through the captured functions (glNative).
    uniform1f: grab(gl2Proto, 'uniform1f') || grab(gl1Proto, 'uniform1f'),
    uniform2f: grab(gl2Proto, 'uniform2f') || grab(gl1Proto, 'uniform2f'),
    uniform1i: grab(gl2Proto, 'uniform1i') || grab(gl1Proto, 'uniform1i'),
    viewport: grab(gl2Proto, 'viewport') || grab(gl1Proto, 'viewport'),
    activeTexture: grab(gl2Proto, 'activeTexture') || grab(gl1Proto, 'activeTexture'),
    texParameteri: grab(gl2Proto, 'texParameteri') || grab(gl1Proto, 'texParameteri'),
    pixelStorei: grab(gl2Proto, 'pixelStorei') || grab(gl1Proto, 'pixelStorei'),
    generateMipmap: grab(gl2Proto, 'generateMipmap') || grab(gl1Proto, 'generateMipmap'),
    getUniformLocation: grab(gl2Proto, 'getUniformLocation') || grab(gl1Proto, 'getUniformLocation'),
    attachShader: grab(gl2Proto, 'attachShader') || grab(gl1Proto, 'attachShader'),
    getShaderParameter: grab(gl2Proto, 'getShaderParameter') || grab(gl1Proto, 'getShaderParameter'),
    getProgramParameter: grab(gl2Proto, 'getProgramParameter') || grab(gl1Proto, 'getProgramParameter'),
    createBuffer: grab(gl2Proto, 'createBuffer') || grab(gl1Proto, 'createBuffer'),
    bindBuffer: grab(gl2Proto, 'bindBuffer') || grab(gl1Proto, 'bindBuffer'),
    bufferData: grab(gl2Proto, 'bufferData') || grab(gl1Proto, 'bufferData'),
    enableVertexAttribArray: grab(gl2Proto, 'enableVertexAttribArray') || grab(gl1Proto, 'enableVertexAttribArray'),
    vertexAttribPointer: grab(gl2Proto, 'vertexAttribPointer') || grab(gl1Proto, 'vertexAttribPointer'),
    getExtension: grab(gl2Proto, 'getExtension') || grab(gl1Proto, 'getExtension'),
  };
  const elementProto = typeof Element !== 'undefined' ? Element.prototype : null;
  const streamProto = typeof ReadableStream !== 'undefined' ? ReadableStream.prototype : null;
  // Reader prototype via one dummy stream (getReader itself is captured
  // separately; a hooked reader.read would otherwise skim chunks).
  const readerProto = (() => {
    try {
      const reader = new ReadableStream().getReader();
      const proto = Object.getPrototypeOf(reader);
      try { reader.releaseLock(); } catch { /* best-effort */ }
      return proto;
    } catch { return null; }
  })();
  const subtleObj = (() => { try { return g.crypto?.subtle || null; } catch { return null; } })();
  const subtleProto = subtleObj ? Object.getPrototypeOf(subtleObj) : null;
  // Property descriptors whose accessors a post-load hook could use to
  // observe off-DOM canvas creation/resizing (the setter receives the
  // canvas itself). Captured for audit comparison; sensitive buffers
  // additionally prefer OffscreenCanvas (constructor-sized).
  const grabDescriptor = (obj, name) => {
    try { return Object.getOwnPropertyDescriptor(obj, name) || null; } catch { return null; }
  };
  const canvasWidthDesc = grabDescriptor(canvasProto, 'width');
  const canvasHeightDesc = grabDescriptor(canvasProto, 'height');
  const smoothingQualityDesc = grabDescriptor(ctx2dProto, 'imageSmoothingQuality');
  return Object.freeze({
    fnToString: Function.prototype.toString,
    // Dispatch primitive: `fn.call(...)` resolves Function.prototype.call
    // AT CALL TIME, so a post-load hook there intercepts every "captured
    // native" invocation despite the captures. All sensitive dispatch
    // goes through the captured Reflect.apply instead (nativeCall).
    reflectApply: grab(g.Reflect, 'apply'),
    fnCall: Function.prototype.call,
    fnApply: Function.prototype.apply,
    fnBind: Function.prototype.bind,
    canvasWidthGet: canvasWidthDesc?.get || null,
    canvasWidthSet: canvasWidthDesc?.set || null,
    canvasHeightGet: canvasHeightDesc?.get || null,
    canvasHeightSet: canvasHeightDesc?.set || null,
    smoothingQualityGet: smoothingQualityDesc?.get || null,
    smoothingQualitySet: smoothingQualityDesc?.set || null,
    fetch: grab(g, 'fetch'),
    // Extra hooks an external review demonstrated: a patched JSON.parse can
    // log every container header (which carries the per-response AES key),
    // a patched attachShadow can downgrade closed roots to open, and a
    // patched SubtleCrypto/getReader can skim plaintext or stream chunks.
    // Capture and USE the pristine versions on sensitive paths.
    jsonParse: (() => { try { return typeof JSON !== 'undefined' && typeof JSON.parse === 'function' ? JSON.parse : null; } catch { return null; } })(),
    attachShadow: grab(elementProto, 'attachShadow'),
    streamGetReader: grab(streamProto, 'getReader'),
    streamReaderRead: grab(readerProto, 'read'),
    responseText: typeof Response !== 'undefined' ? grab(Response.prototype, 'text') : null,
    textDecode: typeof TextDecoder !== 'undefined' ? grab(TextDecoder.prototype, 'decode') : null,
    textEncode: typeof TextEncoder !== 'undefined' ? grab(TextEncoder.prototype, 'encode') : null,
    // WebCrypto: captured so core AES + DPoP signing bypass post-load hooks.
    cryptoObj: (() => { try { return g.crypto || null; } catch { return null; } })(),
    subtle: subtleObj,
    subtleImportKey: grab(subtleProto, 'importKey'),
    subtleEncrypt: grab(subtleProto, 'encrypt'),
    subtleDecrypt: grab(subtleProto, 'decrypt'),
    subtleDigest: grab(subtleProto, 'digest'),
    subtleSign: grab(subtleProto, 'sign'),
    subtleGenerateKey: grab(subtleProto, 'generateKey'),
    subtleExportKey: grab(subtleProto, 'exportKey'),
    getRandomValues: (() => { try { return typeof g.crypto?.getRandomValues === 'function' ? g.crypto.getRandomValues : null; } catch { return null; } })(),
    glGetContextAttributes: glMethods.getContextAttributes,
    createImageBitmap: grab(g, 'createImageBitmap'),
    ImageCtor: typeof Image !== 'undefined' ? Image : null,
    createObjectURL: typeof URL !== 'undefined' ? grab(URL, 'createObjectURL') : null,
    revokeObjectURL: typeof URL !== 'undefined' ? grab(URL, 'revokeObjectURL') : null,
    canvasGetContext: grab(canvasProto, 'getContext'),
    canvasToDataURL: grab(canvasProto, 'toDataURL'),
    canvasToBlob: grab(canvasProto, 'toBlob'),
    ctxDrawImage: grab(ctx2dProto, 'drawImage'),
    ctxGetImageData: grab(ctx2dProto, 'getImageData'),
    ctxPutImageData: grab(ctx2dProto, 'putImageData'),
    // 2D transform/state (red-team C2): save/restore/translate/scale
    // were called directly on the OFF-DOM unscramble buffer's context,
    // so a post-load restore() hook received `this.canvas` — the full
    // clean padded frame. Sensitive paths use ctxNative() now.
    ctxSave: grab(ctx2dProto, 'save'),
    ctxRestore: grab(ctx2dProto, 'restore'),
    ctxTranslate: grab(ctx2dProto, 'translate'),
    ctxScale: grab(ctx2dProto, 'scale'),
    ctxRotate: grab(ctx2dProto, 'rotate'),
    ctxSetTransform: grab(ctx2dProto, 'setTransform'),
    docCreateElement: grab(docProto, 'createElement'),
    glTexImage2D: glMethods.texImage2D,
    glReadPixels: glMethods.readPixels,
    glDrawArrays: glMethods.drawArrays,
    glDrawElements: glMethods.drawElements,
    webgl: Object.freeze(glMethods),
    webgl1: Object.freeze(Object.fromEntries(Object.keys(glMethods).map((name) => [name, grab(gl1Proto, name)]))),
    webgl2: Object.freeze(Object.fromEntries(Object.keys(glMethods).map((name) => [name, grab(gl2Proto, name)]))),
  });
})();

// Route the core's container-header parsing through the captured parser so
// a later JSON.parse hook cannot skim per-response AES keys.
try { useJsonParser(NATIVES.jsonParse); } catch { /* non-fatal */ }
// Same for WebCrypto: core AES import/decrypt uses the captured subtle.
try {
  useWebCrypto(NATIVES.subtle ? {
    subtle: NATIVES.subtle,
    importKey: NATIVES.subtleImportKey,
    encrypt: NATIVES.subtleEncrypt,
    decrypt: NATIVES.subtleDecrypt,
    digest: NATIVES.subtleDigest,
    getRandomValues: NATIVES.getRandomValues,
    cryptoObj: NATIVES.cryptoObj,
  } : null);
} catch { /* non-fatal */ }

// Call a captured SubtleCrypto prototype method with the captured subtle
// object as receiver (post-load hooks on crypto.subtle are bypassed).
export const SUBTLE_CAPTURED = {
  importKey: 'subtleImportKey', encrypt: 'subtleEncrypt', decrypt: 'subtleDecrypt',
  digest: 'subtleDigest', sign: 'subtleSign', generateKey: 'subtleGenerateKey',
  exportKey: 'subtleExportKey',
};
// Captured-Reflect.apply dispatch: immune to post-load hooks on
// Function.prototype.call/apply/bind (which `fn.call(...)` is not).
export function nativeCall(fn, receiver, args) {
  return NATIVES.reflectApply
    ? NATIVES.reflectApply(fn, receiver, args)
    : fn.call(receiver, ...args);
}
export function subtleDo(name, ...args) {
  const fn = NATIVES[SUBTLE_CAPTURED[name]];
  if (fn && NATIVES.subtle) return nativeCall(fn, NATIVES.subtle, args);
  const subtle = globalThis.crypto?.subtle;
  return subtle[name](...args);
}
export const sharedTextEncoder = (() => {
  try { return new TextEncoder(); } catch { return null; }
})();
export function utf8EncodeCaptured(str) {
  return NATIVES.textEncode && sharedTextEncoder
    ? nativeCall(NATIVES.textEncode, sharedTextEncoder, [str])
    : new TextEncoder().encode(str);
}

export function isNativeFn(fn) {
  if (typeof fn !== 'function') return false;
  try { return /\[native code\]/.test(nativeCall(NATIVES.fnToString, fn, [])); } catch { return false; }
}

export function nativeFetch(url, options) {
  return NATIVES.fetch ? nativeCall(NATIVES.fetch, globalThis, [url, options]) : fetch(url, options);
}
export function nativeCreateImageBitmap(source, opts) {
  return NATIVES.createImageBitmap
    ? nativeCall(NATIVES.createImageBitmap, globalThis, [source, opts])
    : createImageBitmap(source, opts);
}
// Size a sensitive off-DOM canvas through the CAPTURED width/height
// setters: a post-load hook on the prototype setters would otherwise
// receive the canvas reference before a single (clean) pixel is drawn
// — and could no-op the width=0 wipes that are supposed to erase it.
export function setCanvasSize(canvas, width, height) {
  if (NATIVES.canvasWidthSet && NATIVES.canvasHeightSet) {
    nativeCall(NATIVES.canvasWidthSet, canvas, [width]);
    nativeCall(NATIVES.canvasHeightSet, canvas, [height]);
  } else {
    canvas.width = width;
    canvas.height = height;
  }
}
export function makeCanvas(ownerDocument) {
  const doc = ownerDocument || document;
  return NATIVES.docCreateElement
    ? nativeCall(NATIVES.docCreateElement, doc, ['canvas'])
    : doc.createElement('canvas');
}
export function getNativeContext(canvas, type, attrs) {
  return NATIVES.canvasGetContext
    ? nativeCall(NATIVES.canvasGetContext, canvas, [type, attrs])
    : canvas.getContext(type, attrs);
}
export function nativeDrawImage(ctx, ...args) {
  return NATIVES.ctxDrawImage ? nativeCall(NATIVES.ctxDrawImage, ctx, args) : ctx.drawImage(...args);
}
// Temporal frame building reads/writes RAW unscrambled RGBA — it must
// not go through the live prototype (a hooked getImageData receives
// the clean frame; a hooked putImageData sees every phase buffer).
export function nativeGetImageData(ctx, x, y, w, h) {
  return NATIVES.ctxGetImageData ? nativeCall(NATIVES.ctxGetImageData, ctx, [x, y, w, h]) : ctx.getImageData(x, y, w, h);
}
export function nativePutImageData(ctx, data, x, y) {
  return NATIVES.ctxPutImageData ? nativeCall(NATIVES.ctxPutImageData, ctx, [data, x, y]) : ctx.putImageData(data, x, y);
}
export function nativeGlDrawArrays(gl, mode, first, count) {
  return NATIVES.glDrawArrays
    ? nativeCall(NATIVES.glDrawArrays, gl, [mode, first, count])
    : gl.drawArrays(mode, first, count);
}
// Captured-method dispatch for every other render-path GL call: a
// post-load hook on WebGL2RenderingContext.prototype can no longer
// observe or alter our uniform values, texture setup, or draws.
export function glNative(gl, name, ...args) {
  const fn = NATIVES.webgl?.[name];
  return fn ? nativeCall(fn, gl, args) : gl[name](...args);
}
export const CTX_NATIVE = {
  save: 'ctxSave', restore: 'ctxRestore', translate: 'ctxTranslate',
  scale: 'ctxScale', rotate: 'ctxRotate', setTransform: 'ctxSetTransform',
};
export function ctxNative(ctx, name, ...args) {
  const fn = NATIVES[CTX_NATIVE[name]];
  return fn ? nativeCall(fn, ctx, args) : ctx[name](...args);
}

/* ================================================================== */
/* Global config + registries                                          */
/* ================================================================== */

/** Canonical browser-requested widths shared with the server/build ladder. */
