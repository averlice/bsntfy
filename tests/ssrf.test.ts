import { describe, expect, it } from 'vitest';
import { validateEndpoint } from '../src/ssrf';

function stubDns(answers: { type: number; data: string }[]) {
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const u = String(input);
    if (u.includes('dns-query')) {
      const type = new URL(u).searchParams.get('type');
      const filtered = answers.filter((a) => (type === 'AAAA' ? a.type === 28 : a.type === 1));
      return new Response(JSON.stringify({ Answer: filtered }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('unexpected', { status: 500 });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = orig;
  };
}

describe('endpoint SSRF validation', () => {
  it('rejects non-https', async () => {
    expect((await validateEndpoint('http://example.com/x')).ok).toBe(false);
    expect((await validateEndpoint('ftp://example.com/x')).ok).toBe(false);
  });

  it('rejects credentials in the URL', async () => {
    expect((await validateEndpoint('https://user:pass@example.com/x')).ok).toBe(false);
  });

  it('rejects private IPv4 literals without network access', async () => {
    for (const ip of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.1', '172.16.5.5', '0.0.0.0', '100.64.0.1', '224.0.0.1']) {
      expect((await validateEndpoint('https://' + ip + '/push')).ok, `${ip} should be rejected`).toBe(false);
    }
  });

  it('allows public IPv4 literals', async () => {
    expect((await validateEndpoint('https://1.2.3.4/push')).ok).toBe(true);
  });

  it('rejects reserved hostnames', async () => {
    for (const h of ['localhost', 'foo.localhost', 'internal.local', 'db.internal', 'print.lan', 'router.home', 'x.test', 'y.invalid']) {
      expect((await validateEndpoint('https://' + h + '/push')).ok, `${h} should be rejected`).toBe(false);
    }
  });

  it('rejects hostnames that resolve to private addresses', async () => {
    const restore = stubDns([{ type: 1, data: '192.168.0.5' }]);
    try {
      expect((await validateEndpoint('https://push.example.com/push/1')).ok).toBe(false);
    } finally {
      restore();
    }
  });

  it('allows hostnames that resolve to public addresses', async () => {
    const restore = stubDns([{ type: 1, data: '34.17.4.8' }]);
    try {
      const v = await validateEndpoint('https://push.example.com/push/1');
      expect(v.ok).toBe(true);
    } finally {
      restore();
    }
  });

  it('rejects unresolvable / empty answers', async () => {
    const restore = stubDns([]);
    try {
      expect((await validateEndpoint('https://nowhere.example.com/push')).ok).toBe(false);
    } finally {
      restore();
    }
  });
});