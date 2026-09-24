export interface EndpointValidation {
  ok: boolean;
  reason?: string;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const a = Number(parts[0]);
  const b = Number(parts[1]);
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 31 && parts[2] === '196') return true;
  if (a === 192 && b === 52 && parts[2] === '193') return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && (b === 51 || b === 8 || b === 6)) return true;
  if (a === 203 && b === 0 && parts[2] === '113') return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIpv6(host: string): boolean {
  const h = host.toLowerCase().replace(/\[|\]/g, '');
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('::ffff:')) {
    const tail = h.slice('::ffff:'.length);
    if (/^[\d.]+$/.test(tail)) return isPrivateIpv4(tail);
    return true;
  }
  if (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true;
  if (h.startsWith('fe') && /^fe[0-9a-f]/.test(h)) return true;
  if (h.startsWith('ff')) return true;
  if (h.startsWith('2001:db8')) return true;
  const firstNib = h.charCodeAt(0);
  const digit = String.fromCharCode(firstNib).toLowerCase();
  if ('23'.includes(digit)) return false;
  return true;
}

function isIpLiteral(host: string): 'v4' | 'v6' | null {
  if (/^[\d.]+$/.test(host) && host.includes('.')) return 'v4';
  if (host.includes(':')) return 'v6';
  return null;
}

async function resolveHost(host: string): Promise<string[] | null> {
  const base = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(host) + '&type=';
  const results = new Set<string>();
  for (const type of ['A', 'AAAA']) {
    try {
      const res = await fetch(base + type, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) continue;
      const body = (await res.json()) as { Answer?: { type?: number; data?: string }[] };
      for (const ans of body.Answer ?? []) {
        if ((ans.type === 1 || ans.type === 28) && typeof ans.data === 'string') results.add(ans.data);
      }
    } catch {
      continue;
    }
  }
  return results.size ? [...results] : null;
}

export async function validateEndpoint(raw: unknown): Promise<EndpointValidation> {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return { ok: false, reason: 'invalid endpoint' };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid url' };
  }
  if (url.protocol !== 'https:') return { ok: false, reason: 'https required' };
  if (url.username || url.password) return { ok: false, reason: 'credentials not allowed' };
  let host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return { ok: false, reason: 'invalid host' };

  const literal = isIpLiteral(host);
  if (literal === 'v4') return isPrivateIpv4(host) ? { ok: false, reason: 'private address' } : { ok: true };
  if (literal === 'v6') return isPrivateIpv6(host) ? { ok: false, reason: 'private address' } : { ok: true };

  if (host === 'localhost') return { ok: false, reason: 'reserved hostname' };
  const reservedSuffixes = ['.localhost', '.local', '.internal', '.lan', '.home', '.localdomain', '.test', '.invalid', '.example', '.home.arpa'];
  if (reservedSuffixes.some((s) => host.endsWith(s))) return { ok: false, reason: 'reserved hostname' };

  const addrs = await resolveHost(host);
  if (!addrs) return { ok: false, reason: 'unresolvable host' };
  for (const addr of addrs) {
    const literal2 = isIpLiteral(addr);
    if (literal2 === 'v4' && isPrivateIpv4(addr)) return { ok: false, reason: 'private address' };
    if (literal2 === 'v6' && isPrivateIpv6(addr)) return { ok: false, reason: 'private address' };
  }
  return { ok: true };
}