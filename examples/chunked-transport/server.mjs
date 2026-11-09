import { createHash, sign } from 'node:crypto';
import { createServer } from 'node:http';

const SHA256 = /^[0-9a-f]{64}$/;
const ASSET_ID = /^[A-Za-z0-9._-]{1,96}$/;
const MAX_CONTAINER_BYTES = 64 * 1024 * 1024;
const MAX_CHUNKS = 256;
const MAX_CHUNK_BYTES = 1024 * 1024;
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'private, no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

/**
 * Small reference origin for signed, bounded chunk manifests.
 * `assets` is an object of assetId -> complete .archx bytes. Authorization is
 * required on every manifest and chunk request; the callback owns the host's
 * entitlement/session policy. For production, use durable storage and bounded
 * streaming reads rather than holding all assets in memory.
 */
export function createChunkedAssetServer({
  assets,
  privateKey,
  authorize,
  chunkBytes = 256 * 1024,
  manifestTtlSec = 300,
  maxContainerBytes = MAX_CONTAINER_BYTES,
}) {
  if (!assets || typeof assets !== 'object' || !privateKey || typeof authorize !== 'function') {
    throw new TypeError('assets, privateKey, and an explicit authorize callback are required');
  }
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 1 || chunkBytes > MAX_CHUNK_BYTES ||
      !Number.isInteger(manifestTtlSec) || manifestTtlSec < 5 || manifestTtlSec > 3600 ||
      !Number.isSafeInteger(maxContainerBytes) || maxContainerBytes < 1 || maxContainerBytes > MAX_CONTAINER_BYTES) {
    throw new RangeError('invalid chunk transport limits');
  }
  const catalog = new Map();
  for (const [assetId, input] of Object.entries(assets)) {
    if (!ASSET_ID.test(assetId)) throw new TypeError(`invalid asset id: ${assetId}`);
    const bytes = Buffer.from(input);
    if (bytes.length < 1 || bytes.length > maxContainerBytes) throw new RangeError(`asset ${assetId} exceeds container bounds`);
    const chunks = [];
    for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
      const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + chunkBytes));
      chunks.push(Object.freeze({ bytes: chunk, length: chunk.length, sha256: digest(chunk) }));
    }
    if (chunks.length > MAX_CHUNKS) throw new RangeError(`asset ${assetId} exceeds chunk count bound`);
    catalog.set(assetId, Object.freeze({ bytes, chunks: Object.freeze(chunks), sha256: digest(bytes) }));
  }

  return createServer(async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD', 'cache-control': 'private, no-store' });
      res.end();
      return;
    }
    let pathname;
    try { pathname = new URL(req.url || '/', 'http://archx.invalid').pathname; }
    catch { res.writeHead(400); res.end(); return; }
    const match = pathname.match(/^\/archx-chunks\/([A-Za-z0-9._-]{1,96})(?:\/(\d+)|\.manifest)$/);
    if (!match) { json(res, 404, { error: 'not found' }); return; }
    const [, assetId, chunkIndexText] = match;
    const asset = catalog.get(assetId);
    if (!asset) { json(res, 404, { error: 'not found' }); return; }
    let authorized = false;
    try { authorized = await authorize(req, assetId) === true; }
    catch { authorized = false; }
    if (!authorized) { json(res, 404, { error: 'not found' }); return; }

    if (chunkIndexText === undefined) {
      const manifest = {
        version: 1,
        assetId,
        expiresAt: new Date(Date.now() + manifestTtlSec * 1000).toISOString(),
        contentLength: asset.bytes.length,
        containerSha256: asset.sha256,
        chunks: asset.chunks.map((chunk, index) => ({
          url: `/archx-chunks/${encodeURIComponent(assetId)}/${index}`,
          length: chunk.length,
          sha256: chunk.sha256,
        })),
      };
      const manifestBytes = Buffer.from(JSON.stringify(manifest));
      const signature = sign('RSA-SHA256', manifestBytes, privateKey);
      const envelope = {
        version: 1,
        manifest: manifestBytes.toString('base64'),
        signature: signature.toString('base64'),
      };
      if (req.method === 'HEAD') {
        const body = Buffer.from(JSON.stringify(envelope));
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-length': body.length,
          'cache-control': 'private, no-store',
          'x-content-type-options': 'nosniff',
        });
        res.end();
      } else json(res, 200, envelope);
      return;
    }

    const chunkIndex = Number(chunkIndexText);
    const chunk = Number.isSafeInteger(chunkIndex) ? asset.chunks[chunkIndex] : null;
    if (!chunk) { json(res, 404, { error: 'not found' }); return; }
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': chunk.length,
      'cache-control': 'private, no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(req.method === 'HEAD' ? undefined : chunk.bytes);
  });
}

export const CHUNKED_TRANSPORT_LIMITS = Object.freeze({
  envelopeBytes: 512 * 1024,
  manifestBytes: 384 * 1024,
  chunks: MAX_CHUNKS,
  chunkBytes: MAX_CHUNK_BYTES,
  containerBytes: MAX_CONTAINER_BYTES,
});
