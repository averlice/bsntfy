# BS Notify

A modern, self-hosted [ntfy](https://ntfy.sh)-style push notification server that runs
entirely on [Cloudflare Workers](https://workers.cloudflare.com) — no VMs, no managed
push service in front, no monthly bill.

Push notifications are delivered directly from the Worker to Android via
[FCM's Web Push (RFC 8030)](https://github.com/web-push-libs/web-push), encrypted with
[RFC 8291 (aes128gcm)](https://www.rfc-editor.org/rfc/rfc8291) and authenticated with
[VAPID (RFC 8292)](https://www.rfc-editor.org/rfc/rfc8292).

- **Account-based** — register with just a password; you get a random 10-digit account
  number that acts as your username.
- **Topics** — per-account topics with publish/read API keys, a short feed, and
  subscriber management.
- **Pairing without passwords** — generate a one-time 6-digit code in the web dashboard
  and redeem it in the app; the app never sees your password.
- **Device tokens** — `push` (subscribe + receive) or `manage` (owner powers incl.
  publish), 30-day expiry, revocable, killed on password change.
- **Hardened** — PBKDF2 (3×100k iterations + per-account salt + server pepper) via a
  Durable Object, SHA-256 token storage, SSRF-guarded subscription endpoints, and
  Durable-Object rate limiting (IP bans, pairing brute-force limits).

## How it works

```
Browser / curl ──▶  Worker (bs-notify)
                       │
                       ├─ Hasher DO        PBKDF2 derivation + compare (pepper)
                       ├─ RateLimiter DO   login/register bans, pairing limits
                       ├─ ACCOUNTS/KEYS    records, API keys, device tokens (SHA-256 ids)
                       ├─ SESSIONS         session tokens (7-day, cookie or Bearer)
                       ├─ TOPICS           topic records, subscribers
                       └─ FEEDS            per-topic message feed (50, 3-day TTL)
                           │
                           └─ FCM/AWS/other Web Push endpoint (aes128gcm + VAPID)
```

## Security model

| Credential | Format | Stored | Expiry | Powers |
| --- | --- | --- | --- | --- |
| Account | `password` + 10-digit number | PBKDF2 hash | — | everything |
| Session | random, cookie (`fy_session`) or `Authorization: Bearer` | SHA-256 | 7 days | everything |
| Device token | `fyd_…` | SHA-256 | 30 days | subscribe; `manage` also owns the account |
| API key | `fy_…` | SHA-256 | — | per-topic `read` / `write` / `readwrite` |
| Pair code | 6 digits | SHA-256 | 10 min, single-use | redeems to a session |

All tokens/keys are shown exactly once (in the token itself) — the server only ever
stores their SHA-256 digest, so a KV dump leaks nothing.

## API (all under `/v1`)

| Method & path | Auth | Description |
| --- | --- | --- |
| `POST /register` | — | `{password}` → `{accountNumber, session}` |
| `POST /login` | — | `{accountNumber, password}` → `{session}` |
| `POST /logout` | session | revoke current session (cookie or Bearer) |
| `GET /account` | session | account info |
| `DELETE /account` | session | delete account + all data (needs `password`) |
| `POST /account/password` | session | change password (revokes device tokens, other sessions) |
| `GET/POST /topics` | session | list / create topics |
| `DELETE /topics/:topic` | session | delete topic + cascade |
| `GET /topics/:topic/keys` · `POST` · `DELETE /:id` | session | API key management |
| `GET /topics/:topic/subscribers` · `DELETE /:id` | session | subscriber management |
| `POST /topics/:topic/subscribe` | device token | `{endpoint, keys?}` → register for push |
| `DELETE /topics/:topic/subscribe/:id` | device token | unsubscribe |
| `GET /messages/:topic` | session/manage or read key | latest feed |
| `POST /publish/:topic` | write key, session, or `manage` device | raw body → feed + push |
| `GET/POST /device-tokens` · `DELETE /:id` | session | device token management |
| `POST /pair-codes` | session | generate 6-digit code |
| `POST /pair-codes/redeem` | — | `{accountNumber, code}` → `{session}` |
| `GET /health` | — | liveness |

Publish example:

```sh
curl -X POST "https://your-domain/v1/publish/news" \
  -H "Authorization: Bearer fy_…" \
  -H "Content-Type: text/plain" \
  -d "hello from curl"
```

## Deploy

1. **Clone & install**

   ```sh
   git clone https://github.com/averlice/bsntfy.git
   cd bsntfy
   npm install
   ```

2. **Generate a VAPID keypair** (used to authenticate Web Push):

   ```sh
   npm run keys:generate
   ```

   → `VAPID_PUBLIC_KEY` (goes in `wrangler.toml` `[vars]`) and `VAPID_PRIVATE_KEY`
   (is a secret).

3. **Generate a pepper** (mixed into password hashing):

   ```sh
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. **Configure** — copy `wrangler.example.toml` to `wrangler.toml`, fill in your
   account id, create the five KV namespaces and paste their ids:

   ```sh
   npx wrangler kv namespace create ACCOUNTS
   npx wrangler kv namespace create SESSIONS
   npx wrangler kv namespace create TOPICS
   npx wrangler kv namespace create KEYS
   npx wrangler kv namespace create FEEDS
   ```

5. **Set secrets**:

   ```sh
   npx wrangler secret put PEPPER
   npx wrangler secret put VAPID_PRIVATE_KEY
   npx wrangler secret put VAPID_SUBJECT   # e.g. mailto:you@example.com
   ```

6. **Deploy** (the Durable Objects migration runs automatically on first deploy):

   ```sh
   npx wrangler deploy
   ```

7. **Custom domain** — attach your zone/route in the Cloudflare dashboard and point it
   at the Worker.

## Local development

Create `.dev.vars` with the same `PEPPER`, `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, and
`VAPID_SUBJECT` values, then:

```sh
npm run dev
```

## Tests

```sh
npm run typecheck   # tsc --noEmit
npm test            # vitest run (encryption, auth, scope, pairing, rate limits)
```

## Notes

- The web UI lives in `public/` and is served by the Worker with no-store caching.
- The `wrangler.toml` (your real ids/account) is gitignored; `wrangler.example.toml`
  is the committed reference.
- This is a personal, research-grade project — audit before trusting it with data you
  care about, and rotate the VAPID keypair you ship to app stores if you ever deploy it.

## License

GPL-3.0-only — see [LICENSE](LICENSE).