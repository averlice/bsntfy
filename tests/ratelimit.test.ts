import { describe, expect, it } from 'vitest';
import { BAN_FAILURES } from '../src/config';
import { RateLimiter } from '../src/ratelimit';
import { fakeDOState } from './helpers';

async function call(rl: RateLimiter, op: 'check' | 'fail' | 'success', acct?: string) {
  const res = await rl.fetch(
    new Request('https://internal/ratelimit', {
      method: 'POST',
      body: JSON.stringify({ op, acct }),
    }),
  );
  return (await res.json()) as { banned: boolean; retryAfterMs: number };
}

describe('RateLimiter DO', () => {
  it('bans an IP after 3 failed attempts and resets on success', async () => {
    const rl = new RateLimiter(fakeDOState(), null as never);

    expect((await call(rl, 'check')).banned).toBe(false);
    for (let i = 0; i < BAN_FAILURES - 1; i++) {
      const r = await call(rl, 'fail', '1234567890');
      expect(r.banned).toBe(false);
    }
    const third = await call(rl, 'fail', '1234567890');
    expect(third.banned).toBe(true);
    expect(third.retryAfterMs).toBeGreaterThan(0);

    const after = await call(rl, 'check');
    expect(after.banned).toBe(true);

    const reset = await call(rl, 'success');
    expect(reset.banned).toBe(false);
    expect((await call(rl, 'check')).banned).toBe(false);
  });

  it('keeps failures below the threshold', async () => {
    const rl = new RateLimiter(fakeDOState(), null as never);
    await call(rl, 'fail', 'aaaaaaaaaa');
    await call(rl, 'fail', 'aaaaaaaaaa');
    const r = await call(rl, 'check');
    expect(r.banned).toBe(false);
  });
});