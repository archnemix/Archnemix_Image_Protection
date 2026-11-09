import { isIP } from 'node:net';

const IPV6_AGGREGATE_MULTIPLIER = 4;

function ipv6Groups(ip) {
  try {
    let address = String(ip || '').toLowerCase();
    const zoneAt = address.indexOf('%');
    if (zoneAt !== -1) address = address.slice(0, zoneAt);
    const v4Tail = address.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (v4Tail) {
      const octets = [Number(v4Tail[1]), Number(v4Tail[2]), Number(v4Tail[3]), Number(v4Tail[4])];
      if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
      const hi = ((octets[0] << 8) | octets[1]).toString(16);
      const lo = ((octets[2] << 8) | octets[3]).toString(16);
      address = address.slice(0, address.length - v4Tail[0].length) + hi + ':' + lo;
    }
    const halves = address.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
    const groups = [...head, ...Array(missing).fill('0'), ...tail];
    if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
    return groups.map((group) => parseInt(group, 16).toString(16));
  } catch { return null; }
}

export function canonicalClientIp(ip) {
  if (typeof ip !== 'string' || !ip) return null;
  let raw = ip.trim();
  const zoneAt = raw.indexOf('%');
  if (zoneAt !== -1) {
    const zone = raw.slice(zoneAt + 1);
    if (!zone || zone.length > 32 || !/^[0-9A-Za-z._-]+$/.test(zone)) return null;
    raw = raw.slice(0, zoneAt);
  }
  const kind = isIP(raw);
  if (kind === 4) return raw;
  if (kind !== 6) return null;
  const groups = ipv6Groups(raw);
  if (!groups) return null;
  const toIpv4 = (hiHex, loHex) => {
    const hi = parseInt(hiHex, 16) || 0;
    const lo = parseInt(loHex, 16) || 0;
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  };
  const zero5 = groups[0] === '0' && groups[1] === '0' && groups[2] === '0' && groups[3] === '0' && groups[4] === '0';
  if ((zero5 && groups[5] === 'ffff') ||
      (groups[0] === '0' && groups[1] === '0' && groups[2] === '0' && groups[3] === '0' && groups[4] === 'ffff' && groups[5] === '0')) {
    return toIpv4(groups[6], groups[7]);
  }
  if (zero5 && groups[5] === '0' && (parseInt(groups[6], 16) || 0) >= 0x0100) {
    return toIpv4(groups[6], groups[7]);
  }
  if (groups[0] === '64' && groups[1] === 'ff9b' && (groups[2] === '0' || groups[2] === '1') &&
      groups[3] === '0' && groups[4] === '0' && groups[5] === '0') {
    return toIpv4(groups[6], groups[7]);
  }
  if (groups[0] === '2002') return toIpv4(groups[1], groups[2]);
  if (groups[0] === '2001' && groups[1] === '0') {
    const hi = (((parseInt(groups[6], 16) || 0) ^ 0xffff) & 0xffff);
    const lo = (((parseInt(groups[7], 16) || 0) ^ 0xffff) & 0xffff);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return groups.join(':');
}

/** Create proxy-aware identities for exact token binding and quota tiers. */
export function createRequestIdentity({ trustProxy = false, trustedProxyHops = 0 } = {}) {
  const requestIp = (req) => {
    const socketIp = String(req.socket?.remoteAddress || '');
    if (trustProxy && trustedProxyHops > 0) {
      const forwarded = req.headers?.['x-forwarded-for'];
      const raw = Array.isArray(forwarded) ? forwarded.join(',') : String(forwarded || '');
      if (raw.length <= 4096) {
        const chain = raw.split(',').map((part) => part.trim()).filter(Boolean);
        // Select from the right by only the number of configured trusted
        // proxy hops; short/missing headers fall back to the socket peer.
        const candidate = chain.length >= trustedProxyHops
          ? chain[chain.length - trustedProxyHops]
          : '';
        const canonical = canonicalClientIp(candidate);
        if (canonical) return canonical;
      }
    }
    return canonicalClientIp(socketIp) || 'unknown';
  };
  const limiterIp = (req) => {
    const ip = requestIp(req);
    if (isIP(ip) !== 6) return ip;
    const groups = ipv6Groups(ip);
    return groups ? `${groups.slice(0, 4).join(':')}::/64` : ip;
  };
  const limiterIpTiers = (req) => {
    const ip = requestIp(req);
    if (isIP(ip) !== 6) return [{ key: ip, mult: 1 }];
    const groups = ipv6Groups(ip);
    if (!groups) return [{ key: ip, mult: 1 }];
    return [
      { key: `${groups.slice(0, 4).join(':')}::/64`, mult: 1 },
      { key: `${groups.slice(0, 3).join(':')}::/48`, mult: IPV6_AGGREGATE_MULTIPLIER },
    ];
  };
  return Object.freeze({ requestIp, limiterIp, limiterIpTiers });
}
