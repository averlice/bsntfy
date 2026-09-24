import { describe, expect, it } from 'vitest';
import { dummyPhc, hashPasswordToPhc, verifyPhc } from '../src/hasher';

describe('pbkdf2 password hashing', () => {
  it('dummy phc is a valid encoded hash that fails verification', async () => {
    const phc = dummyPhc();
    expect(phc.startsWith('$pbkdf2$sha256$i=')).toBe(true);
    const ok = await verifyPhc('any password', phc, '');
    expect(ok).toBe(false);
  });

  it('pepper is required: different pepper means verification fails', async () => {
    const phc = await hashPasswordToPhc('correct horse battery staple', 'pepper-A');
    expect(phc).toMatch(/^\$pbkdf2\$sha256\$i=\d+\$r=\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    const samePepper = await verifyPhc('correct horse battery staple', phc, 'pepper-A');
    const wrongPepper = await verifyPhc('correct horse battery staple', phc, 'pepper-B');
    const wrongPassword = await verifyPhc('wrong', phc, 'pepper-A');
    expect(samePepper).toBe(true);
    expect(wrongPepper).toBe(false);
    expect(wrongPassword).toBe(false);
  });

  it('rejects malformed phc strings', async () => {
    expect(await verifyPhc('anything', 'garbage', '')).toBe(false);
    expect(await verifyPhc('anything', '$pbkdf2$sha256$i=0$salt$derived', '')).toBe(false);
  });
});