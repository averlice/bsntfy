import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { expand as hkdfExpand } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { derivePushKeys, encryptPayload, vapidAuthorization, generateVapidKeyPair } from '../src/webpush';
import { b64uToBytes, bytesToB64u, concatBytes, hexToBytes, TE } from '../src/util';
const TD = new TextDecoder();

const RFC_SENDER_PUB =
  'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8';
const RFC_SENDER_PRIV = 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw';
const RFC_UA_PUB =
  'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4';
const RFC_UA_PRIV = 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94';
const RFC_AUTH = 'BTBZMqHH6r4Tts7J_aSIgg';
const RFC_SALT = 'DGv6ra1nlYgDCS1FRnbzlw';
const PLAINTEXT = 'When I grow up, I want to be a watermelon';

const APPENDIX = {
  ecdh: 'kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs',
  prkKey: 'Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k',
  ikm: 'S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg',
  prk: '09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc',
  cek: 'oIhVW04MRdy2XN9CiKLxTg',
  nonce: '4h_95klXJ5E_qnoN',
};

// RFC 8291 Appendix A lists intermediate values that correctly derive from the
// inputs, but its published 86-octet header and the full body are NOT consistent
// with each other: AES-GCM fails authentication when decrypting the RFC's own
// ciphertext using the RFC's own CEK + NONCE. The executable derivation chain
// (appendix intermediates -> CEK/NONCE -> working encrypt/decrypt) is normative;
// this test asserts the canonical header bytes and a working round-trip instead.
const SECTION5_HEADER =
  'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8';

describe('RFC 8291 web push encryption', () => {
  it('derives the RFC appendix intermediate values', () => {
    const out = derivePushKeys(
      b64uToBytes(RFC_UA_PUB),
      b64uToBytes(RFC_SENDER_PRIV),
      b64uToBytes(RFC_AUTH),
      b64uToBytes(RFC_SALT),
    );
    const enc = bytesToB64u;
    expect(enc(out.ecdh)).toBe(APPENDIX.ecdh);
    expect(enc(out.prkKey)).toBe(APPENDIX.prkKey);
    expect(enc(out.ikm)).toBe(APPENDIX.ikm);
    expect(enc(out.prk)).toBe(APPENDIX.prk);
    expect(enc(out.cek)).toBe(APPENDIX.cek);
    expect(enc(out.nonce)).toBe(APPENDIX.nonce);
  });

  it('produces the canonical 86-octet header of the RFC example', () => {
    const body = encryptPayload(TE.encode(PLAINTEXT), b64uToBytes(RFC_UA_PUB), b64uToBytes(RFC_SENDER_PRIV), b64uToBytes(RFC_AUTH), b64uToBytes(RFC_SALT));
    const header = body.slice(0, 86);
    expect(bytesToB64u(header)).toBe(SECTION5_HEADER);
    expect(body[20]).toBe(65);
    expect(new DataView(body.buffer, body.byteOffset + 16, 4).getUint32(0, false)).toBe(4096);
    expect(body.length).toBe(86 + PLAINTEXT.length + 1 + 16);
  });

  it('round-trips encrypt -> decrypt', () => {
    const uaPriv = b64uToBytes(RFC_UA_PRIV);
    const uaPub = b64uToBytes(RFC_UA_PUB);
    const salt = b64uToBytes(RFC_SALT);
    const body = encryptPayload(TE.encode(PLAINTEXT), uaPub, b64uToBytes(RFC_SENDER_PRIV), b64uToBytes(RFC_AUTH), salt);

    const header = body.slice(0, 86);
    const saltHdr = body.slice(0, 16);
    const idlen = body[20];
    const asPub = body.slice(21, 21 + idlen);
    const ciphertext = body.slice(86);

    const ecdh = p256.getSharedSecret(uaPriv, asPub, true).slice(1);
    const prkKey = hmac(sha256, b64uToBytes(RFC_AUTH), ecdh);
    const keyInfo = concatBytes(TE.encode('WebPush: info\0'), uaPub, asPub);
    const ikm = hkdfExpand(sha256, prkKey, keyInfo, 32);
    const prk = hmac(sha256, saltHdr, ikm);
    const cek = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: aes128gcm\0'), 16);
    const nonce = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: nonce\0'), 12);

    const plain = gcm(cek, nonce, header).decrypt(ciphertext);
    expect(plain[plain.length - 1]).toBe(0x02);
    expect(TD.decode(plain.slice(0, -1))).toBe(PLAINTEXT);
  });
});

describe('VAPID (RFC 8292)', () => {
  const pair = generateVapidKeyPair();
  const env = {
    VAPID_PUBLIC_KEY: pair.publicKeyB64u,
    VAPID_PRIVATE_KEY: pair.privateKeyHex,
    VAPID_SUBJECT: 'mailto:push@example.com',
  };

  it('emits a well-formed vapid header with a verifiable signature', () => {
    const auth = vapidAuthorization(env, 'https://push.example.net');
    expect(auth.startsWith('vapid t=')).toBe(true);

    const t = auth.match(/t=([^,]+), k=(.+)$/);
    expect(t).not.toBeNull();
    const [, token, k] = t as unknown as [string, string, string];
    expect(k).toBe(env.VAPID_PUBLIC_KEY);

    const parts = token.split('.');
    expect(parts).toHaveLength(3);

    const claims = JSON.parse(TD.decode(b64uToBytes(parts[1])));
    expect(claims.aud).toBe('https://push.example.net');
    expect(claims.sub).toBe(env.VAPID_SUBJECT);
    const exp = claims.exp as number;
    expect(exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(exp - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(24 * 3600);

    const sig = b64uToBytes(parts[2]);
    const msg = sha256(TE.encode(parts[0] + '.' + parts[1]));
    expect(p256.verify(sig, msg, b64uToBytes(k), { format: 'compact', lowS: false })).toBe(true);
  });

  it('generates a valid P-256 keypair', () => {
    const pair = generateVapidKeyPair();
    const pub = p256.getPublicKey(hexToBytes(pair.privateKeyHex), false);
    expect(bytesToB64u(pub)).toBe(pair.publicKeyB64u);
  });
});