import { p256 } from '@noble/curves/p256';
import { gcm } from '@noble/ciphers/aes';
import { expand as hkdfExpand } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import type { Env, SubRecord } from './env';
import { b64uToBytes, bytesToB64u, concatBytes, hexToBytes, TE, u32be, bytesToHex } from './util';

const RS = 4096;
const EMPTY_SALT = new Uint8Array(0);

export interface PushKeys {
  ecdh: Uint8Array;
  prkKey: Uint8Array;
  ikm: Uint8Array;
  prk: Uint8Array;
  cek: Uint8Array;
  nonce: Uint8Array;
}

export function derivePushKeys(uaPublic: Uint8Array, asPrivate: Uint8Array, authSecret: Uint8Array, salt: Uint8Array): PushKeys {
  const asPublic = p256.getPublicKey(asPrivate, false);
  const ecdh = p256.getSharedSecret(asPrivate, uaPublic, true).slice(1);
  const prkKey = hmac(sha256, authSecret, ecdh);
  const keyInfo = concatBytes(TE.encode('WebPush: info\0'), uaPublic, asPublic);
  const ikm = hkdfExpand(sha256, prkKey, keyInfo, 32);
  const prk = hmac(sha256, salt, ikm);
  const cek = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: nonce\0'), 12);
  return { ecdh, prkKey, ikm, prk, cek, nonce };
}

export function encryptPayload(plaintext: Uint8Array, uaPublic: Uint8Array, asPrivate: Uint8Array, authSecret: Uint8Array, salt: Uint8Array): Uint8Array {
  const asPublic = p256.getPublicKey(asPrivate, false);
  const ecdh = p256.getSharedSecret(asPrivate, uaPublic, true).slice(1);
  const prkKey = hmac(sha256, authSecret, ecdh);
  const keyInfo = concatBytes(TE.encode('WebPush: info\0'), uaPublic, asPublic);
  const ikm = hkdfExpand(sha256, prkKey, keyInfo, 32);
  const prk = hmac(sha256, salt, ikm);
  const cek = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdfExpand(sha256, prk, TE.encode('Content-Encoding: nonce\0'), 12);
  const header = concatBytes(salt.length ? salt : EMPTY_SALT, u32be(RS), new Uint8Array([65]), asPublic);
  const cipher = gcm(cek, nonce, header);
  const ciphertext = cipher.encrypt(concatBytes(plaintext, new Uint8Array([0x02])));
  return concatBytes(header, ciphertext);
}

let cachedVapid: { expiresAtSec: number; value: string } | null = null;

export interface VapidBundle {
  publicKeyB64u: string;
  privateKeyHex: string;
}

export function generateVapidKeyPair(): VapidBundle {
  const priv = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(priv, false);
  return { publicKeyB64u: bytesToB64u(pub), privateKeyHex: bytesToHex(priv) };
}

export function vapidAuthorization(env: { VAPID_PUBLIC_KEY: string; VAPID_PRIVATE_KEY: string; VAPID_SUBJECT: string }, origin: string): string {
  const nowSec = Math.floor(Date.now() / 1000);
  if (cachedVapid && cachedVapid.expiresAtSec > nowSec) return cachedVapid.value;
  const exp = nowSec + 12 * 3600;
  const headerPart = bytesToB64u(TE.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claimsPart = bytesToB64u(TE.encode(JSON.stringify({ aud: origin, exp, sub: env.VAPID_SUBJECT })));
  const signingInput = headerPart + '.' + claimsPart;
  const sig = p256.sign(sha256(TE.encode(signingInput)), hexToBytes(env.VAPID_PRIVATE_KEY), { lowS: false });
  const token = signingInput + '.' + bytesToB64u(sig.toCompactRawBytes());
  cachedVapid = { expiresAtSec: exp - 7200, value: `vapid t=${token}, k=${env.VAPID_PUBLIC_KEY}` };
  return cachedVapid.value;
}

export async function deliverPush(env: Env, sub: SubRecord, plaintext: Uint8Array): Promise<Response> {
  const endpoint = new URL(sub.endpoint);
  const headers = new Headers({ TTL: '86400', 'Content-Type': 'application/octet-stream' });
  let body: Uint8Array = plaintext;
  if (sub.p256dh && sub.auth) {
    const salt = randomBytes(16);
    const asPrivate = p256.utils.randomSecretKey();
    body = encryptPayload(plaintext, b64uToBytes(sub.p256dh), asPrivate, b64uToBytes(sub.auth), salt);
    headers.set('Content-Encoding', 'aes128gcm');
  }
  headers.set('Authorization', vapidAuthorization(env, endpoint.origin));
  const res = await fetch(endpoint.toString(), {
    method: 'POST',
    headers,
    body,
    signal: AbortSignal.timeout(10_000),
  });
  return res;
}