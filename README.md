# MetricCupid Push Relay

A small, self-hostable server for the [MetricCupid](https://github.com/dzaczek) macOS app with two
independent APIs:

- **v1** (`/v1/notify`): a signed relay to the [Pushover](https://pushover.net) API. Described
  first, below.
- **v2** ("MetricCupid Push", `/v2/*`): an end-to-end encrypted mailbox and APNs sender for two-way
  communication between the Mac app and the MetricCupid iPhone / Apple Watch app (alerts with
  Acknowledge / Mute / Open buttons, commands back to the Mac). See [v2](#v2-metriccupid-push) and the
  normative [PROTOCOL.md](PROTOCOL.md).

```
MetricCupid (Mac) --signed JSON--> metriccupid-push --form POST--> api.pushover.net --> iPhone / Apple Watch
```

- Pushover app token and user key live **only on the server** (environment variables). The Mac knows a
  relay URL and a shared secret.
- Several Macs can share one relay.
- The relay adds server-side **dedup** and a **quota guard**, so a flapping alert cannot burn through
  the Pushover monthly limit.
- Single static Rust binary in a distroless image, non-root, read-only filesystem, roughly 10 MB.

Limitation: the relay only forwards what the Mac sends. If the Mac is asleep, nothing is sent.

## Quick start (Docker Compose)

```sh
git clone https://github.com/dzaczek/metriccupid-push && cd metriccupid-push
cp .env.example .env
openssl rand -hex 32          # use the output as RELAY_SECRETS
$EDITOR .env                  # PUSHOVER_APP_TOKEN, PUSHOVER_USER_KEY, RELAY_SECRETS
docker compose up -d --build
curl http://127.0.0.1:8080/healthz      # -> ok
```

Send a test notification (needs `bash`, `openssl`, `curl`):

```sh
RELAY_URL=http://127.0.0.1:8080 RELAY_SECRET=<your secret> \
  scripts/sign.sh '{"title":"Test","message":"Hello from the relay","priority":0}'
# {"status":"sent"}
# HTTP 200
```

The relay listens on `127.0.0.1:8080` only. To reach it from other machines, use a Cloudflare Tunnel
(recommended) or a reverse proxy; see [Cloudflare](#cloudflare).

Without Compose:

```sh
docker build -t metriccupid-push .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env -p 127.0.0.1:8080:8080 metriccupid-push
```

Or from source: `cargo build --release && ./target/release/metriccupid-push` (reads the same
environment variables).

## Configuration

All configuration is via environment variables. Invalid values stop the relay at startup with a
message naming the variable (secret values are never printed). v1 is enabled when any of
`PUSHOVER_APP_TOKEN`, `PUSHOVER_USER_KEY`, `RELAY_SECRETS` is set (then all three are required); with
none of them set, `/v1/notify` returns `404` and only v2 runs. The v2 variables are listed under
[v2 configuration](#v2-configuration).

| Variable | Default | Description |
|---|---|---|
| `PUSHOVER_APP_TOKEN` | required for v1 | Pushover application API token. |
| `PUSHOVER_USER_KEY` | required for v1 | Pushover user or group key. |
| `RELAY_SECRETS` | required for v1 | Comma-separated HMAC secrets, each at least 32 characters. Any of them is accepted, so you can rotate without downtime (add new, update clients, remove old). |
| `BIND` | `0.0.0.0:8080` | Listen address. |
| `TRUST_PROXY` | `none` | How to find the client IP: `none` (TCP peer), `cloudflare`, or `xff:<cidr>[,<cidr>...]`. See [Client IP](#client-ip). |
| `CF_REFRESH` | `false` | With `cloudflare`: fetch `cloudflare.com/ips-v4` and `ips-v6` at startup; on any error the built-in list is used. |
| `CF_IPS_EXTRA` | empty | With `cloudflare`: extra CIDRs trusted to send `CF-Connecting-IP` (e.g. the cloudflared container network). |
| `MODE` | `selfhosted` | `selfhosted` or `hosted`. In `hosted`, `/v1/notify` returns `501`; v2 runs with the licence gate and the gateway endpoint (see [v2 configuration](#v2-configuration)). |
| `ALLOW_EMERGENCY` | `false` | Allow priority `2` (Pushover emergency: repeats every 60 s for up to 1 h until acknowledged). Otherwise `403`. |
| `DEDUP_WINDOW_SECS` | `300` | A second request with the same `dedup_key` inside this window is answered `deduplicated` and not sent. `0` disables. |
| `QUOTA_RESERVE` | `500` | When Pushover's `X-Limit-App-Remaining` drops below this, only priority `>= 1` is sent; lower priorities get `503`. |
| `RATE_GLOBAL_PER_SEC` / `RATE_GLOBAL_BURST` | `50` / `100` | Token bucket for all requests. |
| `RATE_IP_PER_SEC` / `RATE_IP_BURST` | `5` / `20` | Token bucket per client IP (IPv6 grouped by /64). Checked before authentication. |
| `RATE_SECRET_PER_SEC` / `RATE_SECRET_BURST` | `2` / `30` | Token bucket per relay secret (after authentication). |
| `AUTH_BAN_THRESHOLD` | `10` | Auth failures from one IP within the window that trigger a ban. |
| `AUTH_BAN_WINDOW_SECS` | `900` | Window for counting auth failures. |
| `AUTH_BAN_SECS` | `900` | Ban length. Banned IPs get `429` with `Retry-After`. |
| `LOG_FORMAT` | `text` | `text` or `json`. |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, `trace`. |
| `PUSHOVER_API_URL` | `https://api.pushover.net/1/messages.json` | Override for tests only. |
| `TUNNEL_TOKEN` | empty | Used by the `cloudflared` Compose service only. |

Fixed limits: request body 8 KB (`413`), request timeout 10 s, 64 requests in flight, upstream timeout
8 s.

## API

### `POST /v1/notify`

Headers: `Content-Type: application/json`, `X-MC-Timestamp`, `X-MC-Signature` (see [Signing](#signing)).

```json
{
  "title": "web01: Disk full",
  "message": "/var at 99%",
  "priority": 1,
  "url": "https://grafana.example/d/abc",
  "url_title": "Open dashboard",
  "device": "iphone",
  "sound": "siren",
  "dedup_key": "web01/disk/critical"
}
```

| Field | Rules |
|---|---|
| `message` | required, 1 to 1024 characters, not blank |
| `title` | optional, up to 250 characters |
| `priority` | optional, integer `-2..=2`, default `0` |
| `url` | optional, up to 512 characters, absolute `http`/`https` URL |
| `url_title` | optional, up to 100 characters |
| `device` | optional, up to 25 characters, `[A-Za-z0-9_-]` |
| `sound` | optional, up to 32 characters, `[A-Za-z0-9_-]` |
| `dedup_key` | optional, up to 128 characters |

Unknown fields are rejected.

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status":"sent"}` | Accepted by Pushover. |
| `200` | `{"status":"deduplicated"}` | Same `dedup_key` already sent within `DEDUP_WINDOW_SECS`. |
| `400` | `{"error":"invalid_request","detail":"..."}` | Validation failed. |
| `401` | `{"error":"unauthorized"}` | Missing/invalid signature, timestamp out of range, or replay. Deliberately generic. |
| `403` | `{"error":"emergency_not_allowed"}` | Priority 2 while `ALLOW_EMERGENCY=false`. |
| `413` | | Body larger than 8 KB. |
| `429` | `{"error":"rate_limited"}` + `Retry-After` | Rate limit hit or IP banned. |
| `501` | `{"error":"hosted mode not available yet"}` | `MODE=hosted`. |
| `502` | `{"error":"upstream_error"}` | Pushover unreachable or rejected the message. A failed send does not consume the `dedup_key`. |
| `503` | `{"error":"quota_reserve"}` | Quota guard active and priority < 1. |

### `GET /healthz`

`200 ok`. No authentication, no information. Everything else returns `404`. There is no CORS.

## Signing

Every `POST /v1/notify` must carry:

- `X-MC-Timestamp`: current Unix time in seconds (decimal digits).
- `X-MC-Signature`: lowercase hex of `HMAC-SHA256(secret, message)`, where

```
message = "{timestamp}\n{METHOD}\n{path}\n{raw body}"
```

`METHOD` is `POST`, `path` is `/v1/notify` (no host, no query), and `raw body` is the exact bytes
sent. There is no trailing newline after the body.

The relay:

1. rejects timestamps more than 300 s away from its clock (keep clients on NTP);
2. tries every secret in `RELAY_SECRETS` with a constant-time comparison;
3. remembers accepted signatures for 10 minutes and rejects repeats (replay protection). To send the
   same body twice, use a new timestamp.

**Test vector** (every client implementation must reproduce it):

| | |
|---|---|
| secret | `test-secret-0123456789abcdef0123456789` |
| timestamp | `1700000000` |
| method | `POST` |
| path | `/v1/notify` |
| body | `{"title":"t","message":"m","priority":0}` |
| signature | `defa640d01d4dacbfb3044a69adaee459908302676876b7ad847840e49ea89e1` |

Check with openssl:

```sh
printf '%s\n%s\n%s\n%s' 1700000000 POST /v1/notify '{"title":"t","message":"m","priority":0}' \
  | openssl dgst -sha256 -hmac test-secret-0123456789abcdef0123456789 -hex
```

Swift (CryptoKit):

```swift
let key = SymmetricKey(data: Data(secret.utf8))
var msg = Data("\(ts)\nPOST\n/v1/notify\n".utf8)
msg.append(body)  // the exact bytes you send
let sig = HMAC<SHA256>.authenticationCode(for: msg, using: key)
    .map { String(format: "%02x", $0) }.joined()
```

`scripts/sign.sh` signs and sends a body with curl (`SIGN_ONLY=1` prints the headers,
`MC_TS=<ts>` fixes the timestamp).

## v2: MetricCupid Push

Two-way, end-to-end encrypted channel between the Mac app and the iPhone / Apple Watch app. The
normative spec is [PROTOCOL.md](PROTOCOL.md); the Swift apps test against
[test-vectors/v2.json](test-vectors/v2.json).

```
  macOS app                          metriccupid-push                         iPhone / Watch
 +-----------+   POST /v2/messages   +------------------------+   APNs push   +---------------+
 | Icinga /  |---(sealed alert)----->| mailbox (SQLite, 24 h) |-------------->| Notification  |
 | Alert-    |                       | APNs sender:           |  (ciphertext) | Service Ext.  |
 | manager   |                       |  direct | gateway |mock|               | decrypts,     |
 |           |   WebSocket           | command queue (1 h)    | POST          | shows actions |
 | executes  |<--/v2/stream----------|                        |<--/v2/commands| Ack/Mute/Open |
 | ack/mute  |   (sealed command)    |                        |  (sealed)     |               |
 |           |---POST /v2/messages-->|                        |-------------->| result        |
 +-----------+   (sealed result)     +------------------------+   APNs push   +---------------+
       \___________ group secret shared via iCloud Keychain (never sent) ___________/
```

- Keys: the Mac creates a 32-byte group secret and syncs it to the phone through iCloud Keychain.
  Both derive `enc_key` (ChaCha20-Poly1305) and `auth_key` (request HMAC) with HKDF. The server only
  gets `auth_key` and cannot derive `enc_key`.
- The server stores ciphertext, ids, device tokens and timestamps, never plaintext.
- If the phone's extension does not run, the app fetches missed messages from the mailbox
  (`GET /v2/messages?since=`). If the Mac is offline, commands wait up to 1 h and the phone shows
  "Mac offline, queued".
- Live Activity (Dynamic Island / Lock Screen): the Mac posts the alert counts to
  `POST /v2/activity-state`; the server coalesces them (at most one push per group every 5 s) and
  sends `apns-push-type: liveactivity` pushes to the activity tokens the phone registered
  (`PUT /v2/activities/{device_id}`). This content is **plaintext** (iOS applies it without the
  extension): counts only, plus up to 4 short host / service lines if the user turns that on on the
  Mac. See PROTOCOL.md section 6.10. With `APNS_MODE=direct`, the APNs key's topic must also allow
  `cat.sysop.MetricCupid.push-type.liveactivity` (token-based keys do).

### Deployment options

| | Who sends to APNs | You need | Set |
|---|---|---|---|
| **Hosted** (default in the apps) | `push-metriccupid.sysop.cat` | nothing | in the app: server URL default |
| **Self-hosted** | the hosted gateway, on your behalf | this server | `APNS_MODE=gateway` (default) |
| **Self-hosted + own APNs key** | your server, directly | an Apple Developer APNs key for the app's bundle id (only possible if you build the iOS app yourself) | `APNS_MODE=direct`, `APNS_KEY_P8`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC` |

APNs only accepts pushes signed with the provider key of the team that ships the app, so a
self-hosted server for the App Store app needs the gateway. In gateway mode the mailbox, command queue
and WebSocket stay on your server; the gateway only receives, per push, the device token and the
ciphertext (PROTOCOL.md section 9). `APNS_MODE=mock` records pushes in memory for development and
exposes them at `GET /v2/debug/pushes`.

### v2 configuration

| Variable | Default | Description |
|---|---|---|
| `MODE` | `selfhosted` | `hosted` enables App Store licences (`LICENCE_MODE`), `PUT /v2/licence` and the gateway endpoint `POST /v2/gateway/push`. |
| `APNS_MODE` | `gateway` (`direct` in hosted) | `direct`, `gateway` or `mock`. `gateway` is not allowed with `MODE=hosted`. |
| `APNS_KEY_P8` | required for `direct` | Path to the `.p8` file, or the PEM itself (a one-line PEM with literal `\n` works). |
| `APNS_KEY_ID` | required for `direct` | 10-character key id. |
| `APNS_TEAM_ID` | required for `direct` | 10-character team id. |
| `APNS_TOPIC` | `cat.sysop.MetricCupid` | iOS app bundle id (`apns-topic`). |
| `GATEWAY_URL` | `https://push-metriccupid.sysop.cat` | Gateway for `APNS_MODE=gateway`. |
| `DATA_DIR` | `/data` | Directory for the SQLite database (`metriccupid-push.sqlite3`, WAL). Must be writable. |
| `LICENCE_MODE` | `app_transaction` in hosted, `open` self-hosted | `MODE=hosted` only. `app_transaction`: a group needs a verified App Store purchase of the app (StoreKit `AppTransaction` JWS) to register and to send; unlicensed groups can still read. `open`: anyone (open beta). Self-hosted servers never require a licence. See PROTOCOL.md section 13. |
| `HOSTED_OPEN_REGISTRATION` | `false` | Alias: `true` means `LICENCE_MODE=open` (an error together with `LICENCE_MODE=app_transaction`). |
| `LICENCE_ALLOW_SANDBOX` | `true` | Accept TestFlight (`Sandbox`) transactions. `Xcode` transactions are always refused. Set `false` after the beta. |
| `LICENCE_MAX_GROUPS` | `3` | Groups one purchase may be attached to; more get `403 licence_in_use`. |
| `LICENCE_GRACE_UNTIL` | empty | RFC 3339 time or `YYYY-MM-DD` (UTC). Until then groups without a licence may still send, so beta groups keep working while their Macs attach one. |
| `RATE_V2_MESSAGES_PER_SEC` / `_BURST` | `2` / `60` | Per-group bucket for `POST /v2/messages`. |
| `RATE_V2_COMMANDS_PER_SEC` / `_BURST` | `1` / `20` | Per-group bucket for `POST /v2/commands`. |
| `RATE_V2_GATEWAY_PER_SEC` / `_BURST` | `5` / `50` | Hosted: per-group bucket for gateway pushes. |
| `RATE_V2_GROUPS_PER_HOUR` / `RATE_V2_GROUPS_BURST` | `6` / `3` | Per-IP bucket for `POST /v2/groups`. |
| `WS_PING_SECS` | `30` | WebSocket ping interval; idle streams are closed after 2 intervals + 5 s. |
| `MAC_OFFLINE_GRACE_SECS` | `120` | When a group's last Mac stream drops without a `bye`, wait this long before telling the phones "MetricCupid is offline on your Mac" (reconnects within it stay silent). `0` = immediately. A `bye` (quit, sleep, Phone & Watch turned off) is announced at once. |
| `APNS_PRODUCTION_URL` / `APNS_SANDBOX_URL` | Apple's | Overrides for tests only. |

The v1 per-IP, global and auth-ban limits apply to every v2 route too. Fixed limits: 16 KB v2 body,
10 devices per group, mailbox 24 h / 500 messages, command queue 1 h / 200, 1024 streams.

### Data and backups

The database holds group ids with their `auth_key`, device names and APNs tokens, and ciphertext with
short retention. Losing it means every device has to register again (the Mac re-creates the group
with the same id and key, phones re-register). A backup is optional; if you take one, use
`sqlite3 metriccupid-push.sqlite3 ".backup b.sqlite3"` rather than copying files under WAL. With a
bind mount instead of the named volume, `chown 65532:65532` the directory (the container runs as
`nonroot`).

### Privacy model

The server, and anyone who controls it, can see:

- group ids, device ids, device kind, device names (the apps should send a generic name), APNs tokens
  and environment;
- message/command ids, cursors and the `collapse_id` (it tells which pushes concern the same alert,
  not which alert);
- timing, sizes and counts of messages and commands, and which device sent them;
- `urgency` (critical / normal / silent) and type (alert / result / command): needed for the APNs
  priority, sound and notification category;
- client IP addresses (logged together with the group id);
- whether and when each Mac is connected (`last_seen`). The server itself sends the phones plaintext
  presence notices ("MetricCupid is offline on your Mac" / "back online"); they contain only the
  state, a reason (`quit`, `sleep`, `disabled`, `lost`) and a time, never alert content.
- the Live Activity state in plaintext: how many critical / warning / unknown alerts are active,
  and, only with the Mac's "Show host names on the lock screen (sent unencrypted)" setting, up to 4
  lines of severity + host / service (40 characters each);
- hosted only: the group's licence, i.e. the App Store purchase id (`appTransactionId`),
  environment, original purchase date, original app version and platform (never the JWS or the
  Apple ID; PROTOCOL.md 13.5).

Apart from those opt-in Live Activity lines, it cannot see alert titles, hosts, services, summaries,
URLs, commands or results, and it cannot
forge them: content is sealed with a key it never receives. It can drop, delay or delete messages.
Logs never contain sealed blobs, tokens or keys.

### Cloudflare

- WebSockets work through the Cloudflare proxy (orange cloud) and through Cloudflare Tunnel without
  extra settings. Cloudflare closes WebSocket connections that are idle for about 100 s; the server
  pings every 30 s (`WS_PING_SECS`), which keeps the stream alive. Keep `WS_PING_SECS` well below 100.
- Cloudflare restarts edge servers occasionally, which drops long-lived connections: the Mac app must
  reconnect with backoff and poll `GET /v2/commands` while disconnected (PROTOCOL.md section 7).
- Keep `TRUST_PROXY=cloudflare` so per-IP limits and bans see real client IPs.
- The WAF rule above must allow `/v2/` paths. Do not add a Cloudflare rate-limiting rule tighter than
  your phones' polling plus pushes; the per-group limits already protect the server.
- Do not enable Cloudflare features that rewrite request bodies or query strings: the signature
  covers both.

### Smoke test

```sh
docker build -t metriccupid-push .
docker run --rm -d --name mc-smoke --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e APNS_MODE=mock -p 127.0.0.1:8080:8080 metriccupid-push
SMOKE_URL=http://127.0.0.1:8080 cargo run --example smoke
docker rm -f mc-smoke
```

The example creates a group, registers a Mac and an iPhone, opens the Mac's WebSocket, posts an
alert (and checks the mock push), posts a command from the phone (and checks it arrives on the
WebSocket and decrypts), and posts the result.

## Client IP

The client IP is used for the per-IP rate limit and the auth-failure ban, so it must not be spoofable.

- `TRUST_PROXY=none`: the TCP peer address. Use this when clients connect directly.
- `TRUST_PROXY=cloudflare`: `CF-Connecting-IP` is used **only if the TCP peer is inside a Cloudflare
  range** (built-in list of Cloudflare's published IPv4/IPv6 ranges, optional `CF_REFRESH=true`, plus
  `CF_IPS_EXTRA`). A request from anywhere else with a forged `CF-Connecting-IP` is keyed by its real
  peer address.
- `TRUST_PROXY=xff:10.0.0.0/8,192.168.1.10`: for your own reverse proxies. If the peer is trusted, the
  relay walks `X-Forwarded-For` from the right and uses the first address that is not a trusted proxy.

## Cloudflare

### Option A: Cloudflare Tunnel (recommended)

No inbound port, the origin IP stays private.

1. Cloudflare Zero Trust -> Networks -> Tunnels -> create a tunnel, copy its token.
2. Add a public hostname, e.g. `push.example.com`, service `http://relay:8080`.
3. In `.env`:
   ```
   TUNNEL_TOKEN=<token>
   TRUST_PROXY=cloudflare
   CF_IPS_EXTRA=172.30.53.0/24
   ```
   `172.30.53.0/24` is the Compose network (fixed in `docker-compose.yml`). Requests reach the relay
   from the cloudflared container, and `CF-Connecting-IP` is set by Cloudflare's edge.
4. `docker compose --profile tunnel up -d`

Check the relay logs: `client_ip` should show real client addresses, not `172.30.53.x`. If you leave
`TRUST_PROXY=none`, everything still works, but all clients share one per-IP bucket.

### Option B: Proxied DNS (orange cloud)

1. Point a proxied DNS record at the server; terminate TLS at Cloudflare and use a reverse proxy or
   publish the port.
2. Set `TRUST_PROXY=cloudflare` (optionally `CF_REFRESH=true`).
3. Firewall the origin so **only Cloudflare** can reach it, e.g. with ufw:
   ```sh
   for ip in $(curl -s https://www.cloudflare.com/ips-v4) $(curl -s https://www.cloudflare.com/ips-v6); do
     sudo ufw allow from "$ip" to any port 443 proto tcp
   done
   sudo ufw deny 443/tcp
   ```
   Note: Docker-published ports bypass ufw; bind the container to `127.0.0.1` and put a host reverse
   proxy in front, or use the `DOCKER-USER` iptables chain.

### Cloudflare WAF rules (first line of defence)

- Custom rule, action **Block**:
  `not (http.request.uri.path in {"/v1/notify" "/healthz"} or starts_with(http.request.uri.path, "/v2/"))`
  or `(http.request.uri.path eq "/v1/notify" and http.request.method ne "POST")`. If you also block
  `/v2/debug/` (only present with `APNS_MODE=mock`), nothing legitimate is lost.
- Rate limiting rule: `http.request.uri.path eq "/v1/notify"`, counting by IP, e.g. 30 requests per
  1 minute -> Block for 10 minutes (on the Free plan the period and duration are fixed at 10 s; use
  e.g. 10 requests per 10 s).

The relay's own limits still apply behind Cloudflare.

## Security model and limits

- **Authentication**: HMAC-SHA256 over timestamp, method, path and body; 300 s clock window; replay
  cache of accepted signatures (10 min, up to 100 000 entries, oldest evicted first). Failed checks
  return the same generic `401`.
- **Abuse**: per-IP and global token buckets are checked *before* the HMAC work; per-secret bucket
  after. 10 auth failures from one IP within 15 min ban it for 15 min. All maps are bounded and swept
  every 30 s.
- **Resource limits**: 8 KB body (v1) / 16 KB (v2), 10 s request timeout, 64 concurrent requests
  (WebSocket streams are capped separately at 1024), 8 s Pushover / 5 s APNs timeout, Compose limits
  of 64 MB RAM and 0.5 CPU.
- **Logging**: status, client IP, latency and an outcome label only. Secrets, the Pushover token/user
  key and message contents are never logged.
- **Container**: static binary (SQLite compiled in) on `distroless/static:nonroot`, no shell,
  read-only root with `/data` as the only writable volume, all capabilities dropped,
  `no-new-privileges`. TLS roots are compiled in (rustls + webpki-roots); no OpenSSL.
- **Message privacy**: v1 alert contents pass through the relay and Pushover in plaintext. Run the
  relay yourself if that matters to you, or use v2, which is end-to-end encrypted.
- **Not covered**: volumetric DDoS against an exposed origin (use Cloudflare / a Tunnel), a
  compromised relay secret (rotate it via `RELAY_SECRETS`), a client whose clock is off by more than
  5 minutes.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## MetricCupid setup

Requires MetricCupid 1.30.0 or later. In MetricCupid: **Settings -> Notifications & Popups -> Pushover -> Delivery: Via relay server**.

- **Relay URL**: e.g. `https://push.example.com` (the app appends `/v1/notify`).
- **Secret**: one of the values in `RELAY_SECRETS`. It is stored in the macOS Keychain.
- Press **Send test**.

In relay mode the Pushover token and user key are not needed on the Mac.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # unit tests, tests/api.rs (v1, wiremock as Pushover),
                      # tests/v2.rs (v2, mock APNs + fake clock), tests/vectors.rs
```

`tests/common/mod.rs` is a small reference v2 client (HKDF, sealing, signing) used by the tests and
by `examples/smoke.rs`.

## Roadmap

- Hosted: free tier and subscriptions next to today's `founder` licences (PROTOCOL.md 13.6).
- v2: QR pairing and group key rotation; expiry of inactive groups.
- "Minimal content" option (send only severity and host).
- Server-side alert polling, so notifications arrive while the Mac sleeps.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
