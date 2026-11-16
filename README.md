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
| `CF_IPS_EXTRA` | empty | With `cloudflare`: extra CIDRs trusted to send `CF-Connecting-IP`: the cloudflared container's own address as a `/32` (e.g. `172.30.53.20/32`, fixed in `docker-compose.yml`). An entry that contains a Docker bridge gateway (`x.y.z.1` of its network, e.g. a whole `/24`) is refused at startup, because host-published connections arrive from that address and could then forge the header; other subnets broader than `/29` (IPv6 `/125`) outside Cloudflare log a `SECURITY` warning. |
| `CF_IPS_EXTRA_ALLOW_SUBNET` | `false` | `true` accepts a `CF_IPS_EXTRA` entry that contains the bridge gateway (only if nothing else can reach the relay through it). |
| `MODE` | `selfhosted` | `selfhosted` or `hosted`. In `hosted`, `/v1/notify` returns `501`; v2 runs with the licence gate and the gateway endpoint (see [v2 configuration](#v2-configuration)). |
| `ALLOW_EMERGENCY` | `false` | Allow priority `2` (Pushover emergency: repeats every 60 s for up to 1 h until acknowledged). Otherwise `403`. |
| `DEDUP_WINDOW_SECS` | `300` | A second request with the same `dedup_key` inside this window is answered `deduplicated` and not sent. `0` disables. |
| `QUOTA_RESERVE` | `500` | When Pushover's `X-Limit-App-Remaining` drops below this, only priority `>= 1` is sent; lower priorities get `503`. |
| `RATE_GLOBAL_PER_SEC` / `RATE_GLOBAL_BURST` | `50` / `100` | Token bucket for authenticated requests. v2 checks it only after the signature has verified, so anonymous or failing traffic cannot drain it; v1 checks it before authentication. |
| `RATE_ANON_GLOBAL_PER_SEC` / `RATE_ANON_GLOBAL_BURST` | `20` / `60` | Token bucket for anonymous work: `POST /v2/groups` and requests that fail authentication or are signed before the boot cut-off (those get `429` instead of `401` while it is empty). |
| `RATE_PRE_AUTH_PER_SEC` / `RATE_PRE_AUTH_BURST` | `200` / `400` | Cheap ceiling on all pre-signature work of signed routes (group-key lookup and HMAC), checked right after the per-IP bucket. Group ids found unknown are remembered in memory for 60 s (up to 100 000), so floods of random group ids do not reach SQLite; `POST /v2/groups` clears an id. |
| `RATE_IP_PER_SEC` / `RATE_IP_BURST` | `5` / `20` | Token bucket per client IP (IPv6 grouped by /64). Checked before authentication. |
| `RATE_SECRET_PER_SEC` / `RATE_SECRET_BURST` | `2` / `30` | Token bucket per relay secret (after authentication). |
| `AUTH_BAN_THRESHOLD` | `10` | Auth failures from one IP within the window that trigger a ban. |
| `AUTH_BAN_WINDOW_SECS` | `900` | Window for counting auth failures. |
| `AUTH_BAN_SECS` | `900` | Ban length. Banned IPs get `429` with `Retry-After`. |
| `AUTH_ABUSE_THRESHOLD` | `100` | Anonymous `429` answers to one IP (IPv6 /64) within the abuse window that ban it, like auth failures: the registration limits of `POST /v2/groups` (its per-IP and anonymous buckets) and the anonymous bucket hit by failed authentication. The per-IP bucket of signed routes never counts (many legitimate clients can share one NAT address), nor do group-keyed limits or `POST /v2/gateway/push`. |
| `AUTH_ABUSE_WINDOW_SECS` | `60` | Window for counting those answers. |
| `AUTH_ABUSE_BAN_SECS` | `300` | Ban length after sustained rate limiting. |
| `REPLAY_CAP` | `100000` | Signatures the replay cache holds (10 min each). When it is full of live entries, signed requests get `503 busy` (`Retry-After: 1`) instead of evicting one that could still be replayed. Keep it above `RATE_GLOBAL_PER_SEC × 600 + RATE_GLOBAL_BURST` (a startup warning says so). |
| `MAX_CONNECTIONS` | `8192` | Open TCP connections on the API listener, WebSocket streams included. At the cap the server stops accepting; new clients wait in the listen backlog. Accepted connections get TCP keepalive (60 s idle, 15 s interval). |
| `MAX_CONNECTIONS_PER_IP` | `64` | Open connections per TCP peer (IPv6 /64); more are closed at once. Keyed on the TCP peer, not a forwarded header, so trusted proxies (`TRUST_PROXY`: Cloudflare's ranges, `CF_IPS_EXTRA`, `xff:` networks) are exempt: behind cloudflared every connection comes from the tunnel's address, and the per-client limits then apply to the forwarded client IP. Without `TRUST_PROXY`, a reverse proxy in front counts as one peer. |
| `HEADER_READ_TIMEOUT_SECS` | `10` | A connection must deliver complete request headers within this time (also between keep-alive requests), else it is closed (slowloris). Bodies have their own deadline (below). Applies to the API and the admin listener. |
| `TRUSTED_PROXY_IDLE_TIMEOUT_SECS` | `120` | The same timeout for connections from a trusted proxy (`TRUST_PROXY`: Cloudflare's ranges, `CF_IPS_EXTRA`, `xff:` networks). Must be above 90: cloudflared keeps idle origin connections for 90 s, so the server must never close one first (cloudflared would send a request on a closing socket and answer `502`). |
| `LOG_FORMAT` | `text` | `text` or `json`. |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, `trace`. |
| `PUSHOVER_API_URL` | `https://api.pushover.net/1/messages.json` | Override for tests only. Must be `https://`; `http://` only to `127.0.0.1`, `::1` or `localhost`. |
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
exposes them at `GET /v2/debug/pushes` to loopback clients only (the TCP peer, never a forwarded
header). `MODE=hosted` with `APNS_MODE=mock` logs a `SECURITY` error at startup. Caveat: a reverse
proxy (nginx, Caddy, cloudflared on the host network) on the same host connects from `127.0.0.1`,
so through it the route is reachable by anyone who can reach the proxy; never run mock mode behind a
same-host proxy that is reachable from outside.

### v2 configuration

| Variable | Default | Description |
|---|---|---|
| `MODE` | `selfhosted` | `hosted` enables App Store licences (`LICENCE_MODE`), `PUT /v2/licence` and the gateway endpoint `POST /v2/gateway/push`. |
| `APNS_MODE` | `gateway` (`direct` in hosted) | `direct`, `gateway` or `mock`. `gateway` is not allowed with `MODE=hosted`. |
| `APNS_KEY_P8` | required for `direct` | Path to the `.p8` file, or the PEM itself (a one-line PEM with literal `\n` works). |
| `APNS_KEY_ID` | required for `direct` | 10-character key id. |
| `APNS_TEAM_ID` | required for `direct` | 10-character team id. |
| `APNS_TOPIC` | `cat.sysop.MetricCupid` | iOS app bundle id (`apns-topic`). |
| `GATEWAY_URL` | `https://push-metriccupid.sysop.cat` | Gateway for `APNS_MODE=gateway`. Must be `https://` (every group's `auth_key` goes there); `http://` only to a loopback host. |
| `GATEWAY_OPEN` | `false` | Hosted only: relay APNs for self-hosted servers (`/v2/gateway/push`). Off by default; while off, gateway registrations and pushes get `403 gateway_closed`, so self-hosters need their own APNs key. Only groups registered with `gateway: true` while it is on are gateway groups; an existing group becomes one when its server registers the same `group_id` and key again. **Before rolling back to 0.2.0** (which lacks the gateway checks of PROTOCOL.md section 9) set `GATEWAY_OPEN=false`. |
| `GATEWAY_REQUIRE_LICENCE` | `false` | Hosted gateway, strict mode: a `gateway: true` registration needs a valid licence (`402 licence_required` without one, `403` for an invalid or revoked one). Off (compatible): a licence is optional and only doubles the gateway quotas. Shipped Macs (1.33.3) never send a licence to a self-hosted server, so turn this on only after a Mac release that does. |
| `GATEWAY_SANDBOX_LICENCES_COUNT` | `true` | TestFlight (`sandbox`) licences count as licensed for the gateway (quotas, strict mode). `false`: only App Store (`production`) purchases do. |
| `GATEWAY_ACTIVITY_LINES` | `false` | Keep the Live Activity host/service `lines` on gateway pushes. Off: they are dropped (counts, `start` and its fixed alert stay), so gateway callers cannot put arbitrary text on a Lock Screen. |
| `GATEWAY_APNS_SANDBOX` | `false` | Accept gateway pushes with `env: sandbox` (Xcode development builds only); otherwise `400`. App Store and TestFlight builds use production APNs. |
| `GATEWAY_GLOBAL_PER_SEC` / `_BURST` | `20` / `100` | Bucket shared by all gateway pushes. Gateway pushes do not draw from `RATE_GLOBAL_*`, so they cannot starve hosted users. |
| `GATEWAY_GROUP_PER_HOUR` / `_BURST` | `600` / `100` | Per gateway group and hour, on top of `RATE_V2_GATEWAY_*`. Licensed groups get twice both. |
| `GATEWAY_MAX_TOKENS_PER_GROUP` | `30` | Device / activity tokens one gateway group may have used within 24 h; more get `429 token_limit`. Older bindings free their slot; bindings unused for 7 days are deleted. |
| `GATEWAY_MAX_GROUPS` | `2000` | Gateway groups in total; new ones beyond get `503 gateway_full`. |
| `LICENCE_REVOKED_TX` | empty | Comma-separated purchase ids (`appTransactionId`) refused with `403 licence_invalid` (`reason: revoked`); groups they are already attached to count as unlicensed. Merged with revocations made in the [admin panel](#management). Never logged. |
| `DATA_DIR` | `/data` | Directory for the SQLite database (`metriccupid-push.sqlite3`, WAL). Must be writable. |
| `LICENCE_MODE` | `app_transaction` in hosted, `open` self-hosted | `MODE=hosted` only. `app_transaction`: a group needs a verified App Store purchase of the app (StoreKit `AppTransaction` JWS) to register and to send; unlicensed groups can still read. `open`: anyone (open beta). Self-hosted servers never require a licence. See PROTOCOL.md section 13. |
| `HOSTED_OPEN_REGISTRATION` | `false` | Alias: `true` means `LICENCE_MODE=open` (an error together with `LICENCE_MODE=app_transaction`). |
| `LICENCE_ALLOW_SANDBOX` | `true` | Accept TestFlight (`Sandbox`) transactions. `Xcode` transactions are always refused. Set `false` after the beta. |
| `LICENCE_MAX_GROUPS` | `3` | Groups one purchase may be attached to; more get `403 licence_in_use`. Independently, one purchase is attached to at most 3 new groups per 24 h (deleting a group does not give that back). |
| `LICENCE_GRACE_UNTIL` | empty | RFC 3339 time or `YYYY-MM-DD` (UTC). Until then groups without a licence may still send, so beta groups keep working while their Macs attach one. |
| `RATE_V2_MESSAGES_PER_SEC` / `_BURST` | `2` / `60` | Per-group bucket for `POST /v2/messages`. |
| `RATE_V2_COMMANDS_PER_SEC` / `_BURST` | `1` / `20` | Per-group bucket for `POST /v2/commands`. |
| `RATE_V2_GATEWAY_PER_SEC` / `_BURST` | `1` / `30` | Hosted: per-group bucket for gateway pushes (licensed groups: twice). |
| `RATE_V2_GROUPS_PER_HOUR` / `RATE_V2_GROUPS_BURST` | `6` / `3` | Per-IP bucket for `POST /v2/groups`. |
| `RATE_GROUP_PER_SEC` / `RATE_GROUP_BURST` | `5` / `60` | Per-group bucket over **every** signed route together (checked after the signature, before `RATE_GLOBAL_*`), on top of the per-route buckets: one group cannot use more than its share. `429` with `Retry-After`. |
| `WS_MAX_STREAMS` | `1024` | Open Mac streams on the server; new ones beyond get `503 too_many_streams`. A device replacing its own stream (reconnect) always fits. |
| `WS_MAX_MACS_PER_GROUP` | `3` | Open Mac streams per group; a further Mac gets `429 too_many_group_streams` (its reconnects still fit). |
| `WS_MAX_PER_IP` | `20` | Open Mac streams per client IP (IPv6 /64); beyond: `429 too_many_ip_streams`. |
| `WS_PING_SECS` | `30` | WebSocket ping interval; idle streams are closed after 2 intervals + 5 s. |
| `V2_SNAPSHOT_MAX_BYTES` | `196608` | Max base64 length of a snapshot's `sealed` (`POST /v2/snapshot`, the iPhone's Active tab; PROTOCOL.md 6.6a). 1024 to 1048576. Only that route accepts bodies above 16 KB. |
| `MAC_OFFLINE_GRACE_SECS` | `120` | When a group's last Mac stream drops without a `bye`, wait this long before telling the phones "MetricCupid is offline on your Mac" (reconnects within it stay silent). `0` = immediately. A `bye` (quit, sleep, Phone & Watch turned off) is announced at once. |
| `APNS_PRODUCTION_URL` / `APNS_SANDBOX_URL` | Apple's | Overrides for tests only. `https://`, or `http://` to a loopback host. |

The v1 per-IP, global and auth-ban limits apply to every v2 route too. Fixed limits: 16 KB v2 body,
10 devices per group, mailbox 24 h / 500 messages, command queue 1 h / 200, command ids remembered
25 h (up to 20 000 per group) and message ids 24 h 10 min (up to 5000 per group) after their first
post, 6 "back online" and 12 "Mac offline" presence pushes per group and hour (an offline notice
beyond that waits and is retried, never dropped), 10 attaches per client IP and day for a licence without `appTransactionId`.
Every request body must arrive within 3 s (10 s for `POST /v2/snapshot`), else `408`; then it waits
at most 1 s for one of 256 request slots shared by all routes, else `503 busy` with `Retry-After: 1`.

### Data and backups

The database holds group ids with their `auth_key`, device names and APNs tokens, and ciphertext with
short retention. Losing it means every device has to register again (the Mac re-creates the group
with the same id and key, phones re-register). A backup is optional; if you take one, use
`sqlite3 metriccupid-push.sqlite3 ".backup b.sqlite3"` rather than copying files under WAL. With a
bind mount instead of the named volume, `chown 65532:65532` the directory (the container runs as
`nonroot`).

0.2.3 adds the tables `command_ids` and `message_ids` (id tombstones: group id, id, cursor, first
seen; no content) the same way as the 0.2.1 / 0.2.2 tables (`CREATE TABLE IF NOT EXISTS`, schema
version stays 6), so a rollback to 0.2.2 or 0.2.1 needs no database restore; those versions ignore
the tables (and so lose the duplicate protection of PROTOCOL.md 6.5 / 6.7 while they run).

### Privacy model

The server, and anyone who controls it, can see:

- group ids, device ids, device kind, device names (the apps should send a generic name), APNs tokens
  and environment;
- message/command ids, cursors and the `collapse_id` (it tells which pushes concern the same alert,
  not which alert);
- timing, sizes and counts of messages and commands, and which device sent them;
- `urgency` (critical / normal / silent) and type (alert / result / command): needed for the APNs
  priority, sound and notification category;
- client IP addresses (logged together with the group id). With the [admin panel](#admin-panel)
  enabled, metrics keep only a /24 (IPv4) or /48 (IPv6) prefix and the Cloudflare country;
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
   CF_IPS_EXTRA=172.30.53.20/32
   ```
   `172.30.53.20` is the cloudflared container's fixed address (`docker-compose.yml`). Trust only that
   address, not the whole Compose network: connections to the host-published port arrive from the
   network's gateway (`172.30.53.1`) and could otherwise forge `CF-Connecting-IP`. The relay refuses
   a `CF_IPS_EXTRA` that contains the gateway unless `CF_IPS_EXTRA_ALLOW_SUBNET=true`.
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

## Admin panel

An optional analytics panel for the operator, on its **own listener** (`ADMIN_BIND`, e.g. port
8081): a separate router that has no public API routes, while the public listener has no admin
routes. Alert content is end-to-end encrypted, so the panel shows **metadata only**: groups, devices
(kind, name, APNs environment, online, last seen, app version), licences, push volumes and APNs
errors, message / command / Live Activity counts, HTTP status and latency, WebSocket sessions,
rate limits, auth failures, bans and admin logins. Plain HTML with inline SVG charts, light / dark,
no JavaScript; JSON mirrors under `/admin/api/` and a CSV export of the daily aggregates.

| Page | JSON |
|---|---|
| `/admin/` overview | `/admin/api/overview` |
| `/admin/groups` (filters: `active=24h\|7d\|30d\|inactive`, `licence=none\|licensed\|founder`, `country=CH`, `q=<id prefix>`, `sort=created\|last_active\|requests\|pushes\|devices`, `order=asc\|desc`) | `/admin/api/groups` |
| `/admin/groups/{group_id}` | `/admin/api/groups/{group_id}` |
| `/admin/pushes` | `/admin/api/pushes` |
| `/admin/security` | `/admin/api/security` |
| | `/admin/export/daily.csv` |
| `/admin/bans`, `/admin/gateway`, `/admin/gateway/{group_id}`, `/admin/licences`, `/admin/limits`, `/admin/audit` (management, below) | |

The groups list also filters on `suspended=yes|no`.

### Setup

1. Create the credentials (prompts twice without echo; or pipe the password on stdin):
   ```sh
   docker run --rm -it ghcr.io/dzaczek/metriccupid-push:latest admin-setup --user admin
   # or: cargo run --release -- admin-setup --user admin
   ```
   It prints `ADMIN_USER`, `ADMIN_PASSWORD_HASH` (argon2id), a fresh `ADMIN_TOTP_SECRET` and an
   `otpauth://` URI for your authenticator app (`qrencode -t ansiutf8 '<uri>'` shows it as a QR
   code). Keep the single quotes around the hash in a Compose env file (`$` would be interpolated);
   with `docker run --env-file` they are harmless.
2. Add them to `.env` with `ADMIN_BIND` and `ADMIN_ALLOW_IPS` (below) and restart. The log says
   `admin panel listening`; if something is missing it says `admin panel NOT started: <reason>`
   and the public API runs normally.
3. Open the panel, log in with user, password and the 6-digit code.

| Variable | Default | Description |
|---|---|---|
| `ADMIN_BIND` | unset (panel off) | Listen address of the panel, e.g. `0.0.0.0:8081`. Never publish this port on the host. |
| `ADMIN_USER` | required | Login name. |
| `ADMIN_PASSWORD_HASH` | required | argon2id PHC string from `admin-setup`. |
| `ADMIN_TOTP_SECRET` | required | Base32 TOTP secret (RFC 6238, SHA-1, 6 digits, 30 s) from `admin-setup`. |
| `ADMIN_ALLOW_IPS` | required | Comma-separated CIDRs (IPv4 / IPv6; a bare IP is a /32 or /128) allowed to reach the panel, checked on the real client IP from `TRUST_PROXY`. Anyone else gets the same plain `404` as an unknown public route. Empty: the panel does not start. `0.0.0.0/0` or `::/0` counts as `ADMIN_ALLOW_ANY=true` (same Access requirement and warning). |
| `ADMIN_ALLOW_ANY` | `false` | `true` allows every IP when `ADMIN_ALLOW_IPS` is empty. Only together with `ADMIN_CF_ACCESS_*` (or `ADMIN_ALLOW_ANY_WITHOUT_ACCESS=true`). |
| `ADMIN_CF_ACCESS_TEAM` | unset | Cloudflare Zero Trust team name (`j23`) or team domain (`j23.cloudflareaccess.com`). With `ADMIN_CF_ACCESS_AUD`, every admin request must carry a valid Cloudflare Access JWT, else `404` (see below). Set both or neither. |
| `ADMIN_CF_ACCESS_AUD` | unset | Application Audience (AUD) tag(s) of the Access application, comma-separated. |
| `ADMIN_ALLOW_ANY_WITHOUT_ACCESS` | unset | `ADMIN_ALLOW_ANY=true` without `ADMIN_CF_ACCESS_*`: unset starts the panel with a loud `SECURITY` warning (a future release will refuse), `true` accepts it explicitly (still warns), `false` refuses to start the panel. |
| `ADMIN_SESSION_HOURS` | `12` | Absolute session lifetime. Sessions are in memory: a restart logs you out. |
| `ADMIN_EVENTS_RETENTION_DAYS` | `30` | Raw metric events; daily aggregates are kept 400 days. Cleanup runs hourly. |

### Cloudflare (Tunnel)

1. In the tunnel, add a **second public hostname**, e.g. `push-admin.sysop.cat`, service
   `http://metriccupid-rust:8081` (the container name and `ADMIN_BIND` port; cloudflared reaches it
   over the Docker network, nothing is published on the host).
2. Keep `TRUST_PROXY=cloudflare` and `CF_IPS_EXTRA=<cloudflared container address>/32` (e.g.
   `172.31.250.20/32`, with a fixed `ipv4_address` for cloudflared; not the whole network): the
   allowlist then sees the visitor's `CF-Connecting-IP`. A forged
   `CF-Connecting-IP` from anywhere else is ignored. Do not put the cloudflared network itself in
   `ADMIN_ALLOW_IPS`.
3. Recommended: put a **Cloudflare Access** application (Zero Trust -> Access -> Applications,
   self-hosted, your e-mail / IdP) in front of the admin hostname as an extra layer, and set
   `ADMIN_CF_ACCESS_TEAM` + `ADMIN_CF_ACCESS_AUD` (the AUD tag is on the application's Overview
   page) so the server itself refuses requests that did not pass Access. The panel's own
   allowlist, password and TOTP still apply behind it.
4. Optional WAF rule on the admin hostname: block everything not starting with `/admin`.

```
ADMIN_BIND=0.0.0.0:8081
ADMIN_USER=admin
ADMIN_PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$...'
ADMIN_TOTP_SECRET=...
ADMIN_ALLOW_IPS=203.0.113.7/32,2001:db8:1234::/48
# or, behind Cloudflare Access instead of an IP allowlist:
# ADMIN_ALLOW_ANY=true
# ADMIN_CF_ACCESS_TEAM=myteam
# ADMIN_CF_ACCESS_AUD=<application AUD tag>
```

### Cloudflare Access JWT check

With `ADMIN_CF_ACCESS_TEAM` and `ADMIN_CF_ACCESS_AUD` set, the server verifies the token Access
adds to every request, following Cloudflare's
[Validate JWTs](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/)
guide:

- Token from the `Cf-Access-Jwt-Assertion` header, else the `CF_Authorization` cookie.
- RS256 only; the key is picked by `kid` from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
  (JWKS `keys`). `iss` must be `https://<team>.cloudflareaccess.com`, `aud` must contain a configured
  AUD tag, `exp` is required and `exp` / `nbf` / `iat` are checked with 60 s leeway.
- Keys are cached in memory and refreshed hourly and on an unknown `kid` (key rotation), at most
  one fetch per minute. If they cannot be fetched (also at startup) the panel answers `404` to
  everything and retries every minute; the public API is not affected.
- Missing or invalid token: the same plain `404` as the allowlist, logged as `admin_denied` with the
  reason (`cf_access_missing`, `cf_access_expired`, ...). Tokens are never logged. The verified
  `email` claim is stored with admin login events (Security page); no other claim is kept.

### Management

Besides the read-only pages, the panel can act. Every action is a `POST` form that needs the
session, its CSRF token and the action rate limit (30 per minute, all admins together); the input
is validated next, so a refused input never uses up a code. Then **step-up**: an authenticator
code typed into the form that was not used before (for a login or an action) opens a **step-up
window** on the server-side session: for 5 minutes, and at most 10 actions, the code field may be
left empty. The window is bound to the session, the admin's /24 or /48 and the Cloudflare Access
identity, is shown in the page header, and ends with logout. These always need a fresh code:
licence revoke / restore, changes of `GATEWAY_OPEN`, `GATEWAY_REQUIRE_LICENCE`,
`RATE_GLOBAL_*`, `RATE_ANON_GLOBAL_*`, `RATE_PRE_AUTH_*` and `WS_MAX_STREAMS`, and bans broader than IPv4 /24 or IPv6 /48. Wrong or reused codes count toward the
login lockout (5 per IP in 15 min lock logins *and* actions). Each action, each refused code and
each refused input is written to the **audit log** (`/admin/audit`: time, admin user plus
Cloudflare Access e-mail, /24 or /48, action, target, detail with `stepup=fresh` or
`stepup=window`, outcome), in the same transaction as the change; the panel has no way to edit or
delete it. Rows are kept 90 days, at most 100 000.

| Page | Actions |
|---|---|
| **Bans** | Lists manual bans and the current automatic (auth-failure) bans with their expiry. Ban an IP or CIDR prefix (IPv4 /16 or longer, IPv6 /32 to /64; a longer IPv6 prefix or a single IPv6 address is widened to its /64, like the automatic bans) for 15 min to 30 days with a reason; lift a manual ban; unban an automatic one. Manual bans are stored (table `manual_bans`), survive restarts and are checked before anything else on every public request (`429` with `Retry-After`). |
| **Gateway** | Gateway groups with licence state, join date, token count, last use, pushes sent in the last hour, refusals (`token_bound`, `not_gateway_group`, `token_limit`, ...). Per group: unbind one token (tokens are shown as a SHA-256 fingerprint only), remove the group from the gateway (membership deleted, tokens unbound). Removal is a **reset**, not a block: the group can register again while the gateway is open. Suspension is the block. |
| **Groups** (detail page) | Suspend / unsuspend with a reason. A suspended group gets `403 group_suspended` on every signed route and on `POST /v2/groups` (no re-registration, licence attach or gateway re-add), its streams are closed, nothing is pushed to its phones; its data is kept. |
| **Licences** | Revoke / restore an App Store purchase by its `appTransactionId`. Takes effect at once for groups already using it: hosted groups count as unlicensed (per `LICENCE_MODE`), gateway groups lose the licensed quotas and, with `GATEWAY_REQUIRE_LICENCE=true`, get `402` at push. Purchase ids are never shown, only a fingerprint (first 12 hex digits of the SHA-256). `LICENCE_REVOKED_TX` entries are listed but can only be removed in the environment. |
| **Limits** | Effective values of `RATE_GLOBAL_*`, `RATE_ANON_GLOBAL_*`, `RATE_PRE_AUTH_*` (at least 20), `RATE_IP_*`, `RATE_GROUP_*` (burst at least 10), `WS_MAX_STREAMS` (16 to 100 000), `WS_MAX_MACS_PER_GROUP` (1 to 10), `WS_MAX_PER_IP`, `RATE_V2_GATEWAY_*`, `GATEWAY_GROUP_*`, `GATEWAY_GLOBAL_*`, `GATEWAY_MAX_TOKENS_PER_GROUP`, `GATEWAY_MAX_GROUPS`, `GATEWAY_OPEN` (kill switch) and `GATEWAY_REQUIRE_LICENCE`, with a per-key override applied without a restart (a changed rate replaces its limiter, whose buckets start full) and kept across restarts until **reset to config**. Overrides must stay within fixed ranges (shown on the page; `RATE_GLOBAL_*` cannot go below 20, so the panel cannot throttle the whole public API). |

The management state lives in SQLite tables added like the 0.2.1 gateway tables (`CREATE TABLE IF
NOT EXISTS`, schema version stays 6): `admin_audit`, `manual_bans`, `group_suspensions`,
`revoked_licences`, `limit_overrides`. It is loaded at startup and applies even while the panel is
off. A rollback to 0.2.0 / 0.2.1 opens the same database but ignores these tables, so manual bans,
suspensions, panel revocations and limit overrides are **not enforced** by those versions (put
lasting revocations in `LICENCE_REVOKED_TX` and lasting limits in the environment before a rollback).

### Security model

- **Access, in order**: IP allowlist (real client IP via `TRUST_PROXY`, else `404`), Cloudflare
  Access JWT when configured (else `404`), login form with
  user + argon2id password + **mandatory TOTP** (±1 step, a code is accepted once), then a 256-bit
  random session token in memory, cookie `mc_admin` (`HttpOnly; Secure; SameSite=Strict; Path=/`).
  The session id is replaced at login (no fixation).
- **CSRF**: every POST (login, logout, management actions) needs the per-session token from a
  hidden form field; `SameSite=Strict` is defence in depth. Every other admin route is a read-only
  GET.
- **Step-up**: management actions also need a fresh TOTP code or an open step-up window (see
  [Management](#management));
  inputs are validated strictly (IP / CIDR, group id, duration, reason, numeric ranges) and every
  value shown is HTML-escaped. Purchase ids and APNs tokens are never shown in full.
- **Brute force**: 5 failed logins per IP (IPv6 /64) within 15 min, or 20 in total, lock logins for
  15 min. One message for every failure; constant-time comparisons; one argon2 check at a time.
- **Headers on every response**: `Content-Security-Policy: default-src 'none'; style-src 'self';
  img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`. No scripts, CDNs or web fonts.
- Passwords and TOTP codes are never logged; failed logins log the /24 or /48 network and a reason.

### Metrics

Recorded in the existing request paths with a short in-memory push; a task writes them every 5 s
in one SQLite transaction (tables `events`, `daily_agg`, `client_activity`; PROTOCOL.md 10.1 lists
exactly what is stored). Buffers are bounded (10 000 pending events, 1 000 raw rows per flush,
50 000 counters, 4 096 latency samples; the excess is counted as `dropped` on the overview), and the
`events` table is capped at 1 000 000 rows. Successful polls are counted per day but not stored
row by row. Full client IPs are never stored: only a /24 or /48 prefix and the Cloudflare country.
App versions come from the `X-MC-Client` header (PROTOCOL.md 5.3). Metrics are only collected
while the panel is enabled. The panel queries a separate read-only SQLite connection, so it never
blocks the API.

## Security model and limits

- **Authentication**: HMAC-SHA256 over timestamp, method, path and body; 300 s clock window; replay
  cache of accepted signatures (10 min, up to `REPLAY_CAP` entries; when full, signed requests get
  `503` rather than an entry being evicted). Timestamps more than 60 s before the process started
  are refused (the cache is in memory, so only the last minute before a restart can be replayed
  once after it); a client whose clock lags by more than 60 s gets `401` for at most (lag - 60) s,
  not counted toward a ban but drawn from the anonymous bucket. Failed checks return the same
  generic `401`.
- **Abuse**: the per-IP bucket, then (v2 signed routes) the `RATE_PRE_AUTH_*` ceiling and the
  unknown-group cache, or (v1) the global bucket, are checked *before* the HMAC work; v2 checks the
  per-group and authenticated global buckets after the signature, so failed or anonymous requests
  (which draw from `RATE_ANON_GLOBAL_*`) never starve signed users. 10 auth failures from one IP
  within 15 min ban it for 15 min; 100 anonymous `429`s (registration floods) within 60 s ban it for
  5 min (`AUTH_ABUSE_*`). All maps are bounded and swept every 30 s.
- **Resource limits**: 8 KB body (v1) / 16 KB (v2), bodies read within 3 s (10 s for the snapshot)
  before any work, headers within `HEADER_READ_TIMEOUT_SECS`, 10 s request timeout, 256 request
  slots shared by all routes with a 1 s wait (then `503`), `MAX_CONNECTIONS` open connections
  (`MAX_CONNECTIONS_PER_IP` per untrusted peer; the admin listener: 256 in total, same per-peer and
  header rules), WebSocket streams capped per server, group and
  IP (`WS_MAX_*`), 8 s Pushover / 5 s APNs timeout, Compose limits of 64 MB RAM and 0.5 CPU.
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
