import { p256 } from '@noble/curves/p256';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const HEX = '0123456789abcdef';

function bytesToB64u(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  return s.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
  return s;
}

const priv = p256.utils.randomSecretKey();
const pub = p256.getPublicKey(priv, false);

console.log('VAPID_PUBLIC_KEY=' + bytesToB64u(pub));
console.log('VAPID_PRIVATE_KEY=' + bytesToHex(priv));
console.log('');
console.log('Generate a pepper with:  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
console.log('');
console.log('Paste the VAPID_PUBLIC_KEY into wrangler.toml under [vars] and run:');
console.log('  npx wrangler secret put PEPPER');
console.log('  npx wrangler secret put VAPID_PRIVATE_KEY');
console.log('  npx wrangler secret put VAPID_SUBJECT');