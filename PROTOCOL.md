# MetricCupid Push protocol, version 2

Status: normative for server `metriccupid-push` 0.2 and the MetricCupid macOS and iOS/watchOS apps.
The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

Test vectors: [`test-vectors/v2.json`](test-vectors/v2.json). Every client implementation MUST
reproduce all of them in its unit tests.

## 1. Overview

v2 gives one user's devices (a **group**) a private channel through a server that only handles
ciphertext:

```
Mac --POST /v2/messages (sealed alert)--> server --APNs (sealed)--> iPhone NSE decrypts, shows alert
iPhone action --POST /v2/commands (sealed)--> server --WebSocket--> Mac executes on Icinga/Alertmanager
Mac --POST /v2/messages (sealed result, same collapse id)--> server --APNs--> iPhone replaces the alert
```

- The group secret never leaves the user's devices (synced with iCloud Keychain). The server stores
  only a one-way derived `auth_key`, so it can authenticate requests but cannot decrypt.
- Every payload is sealed with ChaCha20-Poly1305 by the sender and opened by the receiver.
- The server keeps a short mailbox of messages (24 h) and a command queue (1 h) so devices that miss a
  push or a live stream can catch up.

v1 (`POST /v1/notify`, Pushover relay) is unaffected and specified in README.md.

## 2. Group secret and keys

### 2.1 Group secret

A group is created by the **Mac app** (the iOS app never creates groups; it waits for the secret to
sync, which avoids two devices creating two groups at the same time). It generates:

| Field | Value |
|---|---|
| `group_key` | 32 bytes from a CSPRNG |
| `group_id` | 16 bytes from a CSPRNG, base64url without padding (22 characters) |
| `server_url` | e.g. `https://push.metriccupid.sysop.cat` (default) or a self-hosted URL, no trailing slash |

It is stored as one synchronizable generic-password Keychain item:

| Attribute | Value |
|---|---|
| `kSecClass` | `kSecClassGenericPassword` |
| `kSecAttrService` | `cat.sysop.MetricCupid.push` |
| `kSecAttrAccount` | `group` |
| `kSecAttrSynchronizable` | `true` (iCloud Keychain) |
| `kSecAttrAccessGroup` | a keychain access group shared by the Mac and iOS apps (same team) |
| `kSecAttrAccessible` | `kSecAttrAccessibleAfterFirstUnlock` (the Notification Service Extension must read it while the phone is locked) |
| `kSecValueData` | UTF-8 JSON `{"v":1,"group_key":"<base64>","group_id":"<base64url>","server_url":"https://..."}` |

On macOS the item MUST be created in the data protection keychain (`kSecUseDataProtectionKeychain`),
otherwise it does not sync. Key rotation and QR pairing are out of scope for this version.

### 2.2 Derived keys

HKDF-SHA256 (RFC 5869) with input key material `group_key`, salt = UTF-8 `metriccupid-push-v2`,
output length 32 bytes:

| `info` (UTF-8) | Key | Used for | Known to the server |
|---|---|---|---|
| `enc` | `enc_key` | ChaCha20-Poly1305 (section 4) | no |
| `auth` | `auth_key` | request HMAC (section 5) | yes, registered at group creation |
| `collapse` | `collapse_key` | `collapse_id` derivation (section 4.5) | no |

CryptoKit:

```swift
let ikm = SymmetricKey(data: groupKey)
func derive(_ info: String) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: Data("metriccupid-push-v2".utf8),
                           info: Data(info.utf8), outputByteCount: 32)
}
let encKey = derive("enc"), authKey = derive("auth"), collapseKey = derive("collapse")
```

HKDF is one-way: knowing `auth_key` does not reveal `group_key`, `enc_key` or `collapse_key`.

## 3. Identifiers

| Name | Format | Chosen by |
|---|---|---|
| `group_id`, `device_id` | 16 random bytes, base64url, no padding: exactly 22 characters of `[A-Za-z0-9_-]`, canonical (the last character's low 4 bits are zero) | client |
| message / command id (`id`) | 1..=64 characters of `[A-Za-z0-9_-]`; SHOULD be 16 random bytes base64url | sender |
| `collapse_id` | 1..=64 characters of `[A-Za-z0-9_-]` (section 4.5) | Mac |
| `cursor` | unsigned integer, per group and per queue, strictly increasing, never reused | server |

Ids MUST be random. They MUST NOT be derived from alert content (host or service names), because the
server sees them.

Each device generates its `device_id` once and keeps it in its local (non-synced) Keychain.

## 4. Encryption

### 4.1 Algorithm and format

ChaCha20-Poly1305 (RFC 8439), key `enc_key`, a fresh random 12-byte nonce per message. The wire value
`sealed` is the standard base64 (with padding) of the **combined** box:

```
nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes)
```

This is exactly CryptoKit's `ChaChaPoly.SealedBox.combined`:

```swift
let box = try ChaChaPoly.seal(plaintext, using: encKey, authenticating: Data(aad.utf8))
let sealed = box.combined.base64EncodedString()
// open:
let box = try ChaChaPoly.SealedBox(combined: Data(base64Encoded: sealed)!)
let plaintext = try ChaChaPoly.open(box, using: encKey, authenticating: Data(aad.utf8))
```

### 4.2 Associated data

```
AAD = "{group_id}|{type}|{id}"      (UTF-8, no trailing newline)
```

`type` is `alert`, `result` or `command`; `id` is the message or command id sent next to `sealed`.
This binds a ciphertext to its group, type and id: the server cannot move a box to another group,
replay it under another id, or turn a result into an alert.

### 4.3 Plaintext

UTF-8 JSON object. Common fields:

| Field | Type | Rule |
|---|---|---|
| `v` | int | `1` |
| `type` | string | equals the outer type |
| `id` | string | equals the outer id |
| `ts` | int | sender's Unix time in seconds |

`alert` (Mac to phones):

| Field | Type | Rule |
|---|---|---|
| `alert_id` | string | stable id of the alert at its source, e.g. `icinga:web01!disk`, `alertmanager:<fingerprint>` |
| `title` | string | short headline |
| `host` | string | |
| `service` | string, optional | |
| `severity` | string | `critical`, `warning`, `unknown`, `info` or `ok` |
| `source` | string | `icinga`, `alertmanager`, `zabbix`, `grafana`, ... |
| `summary` | string | one or two lines |
| `url` | string, optional | absolute http(s) URL to open the alert in its source UI |
| `state` | string | `firing` or `resolved` |
| `actions` | array of string | commands the Mac will accept for this alert, subset of `ack`, `unack`, `mute`, `unmute`, `open` |

`command` (phone to Mac):

| Field | Type | Rule |
|---|---|---|
| `action` | string | `ack`, `unack`, `mute`, `unmute`, or `open` (optional for Macs to support: bring the alert up on the Mac) |
| `alert_id` | string | from the alert |
| `duration_secs` | int, optional | `mute` only, 60..=604800; default 3600 |

`result` (Mac to phones):

| Field | Type | Rule |
|---|---|---|
| `command_id` | string | id of the command |
| `alert_id` | string | |
| `ok` | bool | |
| `message` | string | human-readable outcome, at most 256 characters |

Receivers MUST ignore unknown fields. Senders SHOULD encode compact JSON.

### 4.4 Receiver rules

A receiver MUST, in this order:

1. open the box with the AAD built from the outer `type` and `id`; drop on failure;
2. check `v == 1`, `type` and `id` equal the outer values;
3. check `|now - ts| <= 86400`; drop older or future messages;
4. drop ids seen before (keep seen ids for at least 24 h for messages, 1 h for commands).

A Mac MUST execute a command only if `action` is in the `actions` it sent for that `alert_id`.
Delivery is at least once (section 7); step 4 makes execution at most once per device.

### 4.5 Collapse id

So that a result (or a re-sent alert) replaces the earlier notification on the phone without telling
the server which alert it is:

```
collapse_id = base64url_nopad( HMAC-SHA256(collapse_key, UTF-8 alert_id)[0..16] )   // 22 characters
```

The Mac SHOULD send the same `collapse_id` for an alert, its updates and the result of a command on
it. The server only sees that two pushes concern the same (unknown) alert.

### 4.6 Size budget

APNs payloads are limited to 4096 bytes. With the fixed payload of section 6.1, a plaintext of up to
2834 bytes fits in the worst case. The Mac MUST keep plaintext at or below **2560 bytes** (truncate
`summary` first); the server answers `413 payload_too_large` otherwise.

## 5. Request authentication

### 5.1 Signature

Every v2 request except `POST /v2/groups` carries:

| Header | Value |
|---|---|
| `X-MC-Timestamp` | Unix time in seconds, decimal digits |
| `X-MC-Signature` | lowercase hex of `HMAC-SHA256(auth_key, string_to_sign)` |
| `X-MC-Group` | `group_id` |
| `X-MC-Device` | the sender's `device_id` (not sent by the gateway, section 9) |

```
string_to_sign = "{timestamp}\n{METHOD}\n{target}\n{group_id}\n{device_id}\n{raw body}"
```

- `METHOD` is upper case. `target` is the path plus `?query` exactly as sent (no scheme, no host),
  e.g. `/v2/messages?since=41&n=7`. `device_id` is empty for gateway requests (the line stays).
- `raw body` is the exact bytes sent; empty for GET and DELETE and for the WebSocket upgrade.
- There is no newline after the body.

The server rejects: a timestamp more than 300 s from its clock; an unknown group; a bad signature;
and any signature it has already accepted in the last 10 minutes (replay). All of these return the
same `401 {"error":"unauthorized"}`. Ten failures from one IP within 15 minutes ban that IP for 15
minutes (`429`).

Consequences for clients:

- A retry MUST be re-signed. Two byte-identical requests in the same second from the same device have
  the same signature and the second one is rejected as a replay. Wait at least one second before
  retrying, or (GET only) add the query parameter `n=<anything 1..=32 chars of [A-Za-z0-9_-]>`, which
  the server ignores; clients SHOULD add a fresh `n` to every poll.
- Keep the clock on NTP.

### 5.2 Why this differs from v1

The v1 string is `"{ts}\n{METHOD}\n{path}\n{body}"`. v2 adds the group and device ids and signs the
query string. Without them, two devices of one group polling the same URL in the same second
produce the same signature and one of them is refused as a replay, and a TLS-terminating proxy could
change `X-MC-Device` (for example to take over another Mac's stream) or the `since` cursor without
breaking the signature.

## 6. HTTP API

All bodies are JSON (`Content-Type: application/json`), at most 16 KB (`413` above). Unknown
request fields are rejected with `400`. Errors are `{"error":"<code>"}`, validation errors add
`"detail"`. Rate-limited responses carry `Retry-After`.

Device-kind rules: "Mac" means a device registered with `kind: "mac"`, "phone" one with
`kind: "ios"`. Requests from a device that is not registered get `403 unknown_device`; from the wrong
kind, `403 wrong_device_kind`.

### 6.1 `POST /v2/groups` (unauthenticated)

```json
{"group_id": "EBESExQVFhcYGRobHB0eHw", "auth_key": "<base64 of the 32-byte auth_key>", "licence": "<optional, reserved>"}
```

| Status | Body | Meaning |
|---|---|---|
| 201 | `{"status":"created"}` | |
| 200 | `{"status":"exists"}` | same id, same key: idempotent retry |
| 409 | `{"error":"group_exists"}` | same id, different key |
| 402 | `{"error":"licence_required"}` | `MODE=hosted` and the licence check refused (today: unless `HOSTED_OPEN_REGISTRATION=true`) |
| 502 | `{"error":"gateway_error"}` | `APNS_MODE=gateway` and the gateway did not accept the registration; retry |
| 429 | `{"error":"rate_limited"}` | per-IP registration limit (default 6 per hour, burst 3) |

`licence` is reserved for an App Store signed transaction (JWS) in a later version and is ignored
today (at most 12 KB).

### 6.2 `PUT /v2/devices/{device_id}`

`X-MC-Device` MUST equal `{device_id}` (devices register themselves).

```json
{"kind": "ios", "name": "iPhone", "apns_token": "<hex>", "apns_env": "production"}
```

| Field | Rule |
|---|---|
| `kind` | `mac` or `ios` |
| `name` | 1..=64 characters, no control characters. Visible to the server: use a generic name. |
| `apns_token` | `ios` only, 64..=200 hex characters (stored lower case). Omit to remove the token. |
| `apns_env` | `sandbox` (development builds) or `production` (TestFlight/App Store); default `production` |

`201 {"status":"created"}`, `200 {"status":"updated"}`, `409 {"error":"device_limit"}` (10 devices
per group). Phones MUST re-register whenever iOS hands them a new token.

### 6.3 `DELETE /v2/devices/{device_id}`

Any registered device of the group may remove any device (e.g. a lost phone). `204`, or
`404 not_found`. A live stream of that device is closed.

### 6.4 `GET /v2/devices`

```json
{"devices": [{"device_id": "...", "kind": "mac", "name": "...", "apns_env": "production",
              "has_token": false, "created_at": 1700000000, "updated_at": 1700000000, "online": true}]}
```

APNs tokens are never returned. `online` and `last_seen` (Macs only): `online` is true while the
Mac has a live stream (section 7); `last_seen` is the Unix time the server last heard from that
stream (connect, any frame or pong, disconnect; written at least every 10 s while connected), `null`
if it never connected.

### 6.4a `GET /v2/status` (any device)

Is a Mac able to receive commands and send alerts right now?

```json
{"mac_online": false, "mac_last_seen": 1700000000,
 "macs": [{"device_id": "...", "online": false, "last_seen": 1700000000}]}
```

`mac_online` is true if any Mac of the group has a live stream; `mac_last_seen` is the latest
`last_seen` of the group's Macs (`null` if none ever connected). Phones SHOULD call it when they come
to the foreground and show "Mac offline since ..." while `mac_online` is false. Section 7a describes
the pushes that tell the phones about changes.

### 6.5 `POST /v2/messages` (Mac)

```json
{"id": "QEFCQ0RFRkdISUpLTE1OTw", "type": "alert", "sealed": "...", "collapse_id": "koQMO1Fi9vmzlQrvqx9WEQ",
 "urgency": "critical", "ttl_secs": 3600}
```

| Field | Rule |
|---|---|
| `type` | `alert` or `result` |
| `sealed` | section 4; at least 28 bytes decoded |
| `collapse_id` | optional, section 4.5 |
| `urgency` | `critical`, `normal` or `silent`; plaintext metadata (section 10) |
| `ttl_secs` | optional, 0..=86400, default 86400; APNs `apns-expiration` = now + ttl (0 = deliver now or never) |

The server stores the message in the group mailbox, then pushes it to every phone with a token and
waits for the APNs answers:

```json
{"status": "stored", "cursor": 42, "pushed": 1, "failed": 0, "unregistered": 0}
```

A repeated `id` (within 24 h) returns `200 {"status":"duplicate","cursor":42}` without a new push.
`413 payload_too_large` if the APNs payload would exceed 4096 bytes (nothing is stored),
`429 rate_limited` above the per-group limit (default 2/s, burst 60). Tokens APNs reports as invalid
are removed (`unregistered`).

APNs payload (built by the server, identical for direct and gateway delivery):

```json
{"aps": {"alert": {"title": "MetricCupid", "body": "New alert"},
         "mutable-content": 1, "category": "MC_ALERT", "sound": "default",
         "interruption-level": "time-sensitive", "thread-id": "mc"},
 "mc": {"id": "<id>", "t": "alert", "s": "<sealed>"}}
```

- `category`: `MC_ALERT` for alerts, `MC_RESULT` for results; `body`: `New alert` / `Command result`
  (shown only if the extension cannot decrypt in time).
- `sound: "default"` unless `urgency` is `silent`; `interruption-level: "time-sensitive"` only for
  `critical`.

APNs request headers: `apns-topic` = `APNS_TOPIC` (default `cat.sysop.MetricCupid`),
`apns-push-type: alert`, `apns-priority: 10` (`5` for `silent`), `apns-expiration`,
`apns-collapse-id` when given. A `410`, or `400` with reason `BadDeviceToken`, removes the token.

The phone's Notification Service Extension decrypts `mc.s` (AAD `"{group_id}|{mc.t}|{mc.id}"`),
applies section 4.4, and replaces title and body. Category `MC_ALERT` offers the actions
Acknowledge (`ack`), Mute 1h (`mute`, 3600 s) and Open (opens `url` on the phone, foreground, no
command), filtered by the alert's `actions`. `MC_RESULT` has no actions.

### 6.6 `GET /v2/messages?since=<cursor>` (any device)

Messages with `cursor > since` (default 0), oldest first, at most 100 per page:

```json
{"messages": [{"cursor": 42, "id": "...", "type": "alert", "sealed": "...", "urgency": "critical",
               "collapse_id": "...", "received_at": 1700000000}],
 "cursor": 42, "more": false}
```

Pass the returned `cursor` as the next `since`. Used by the app's recent list and when the extension
could not run. Retention: 24 h and at most 500 messages per group (oldest dropped).

### 6.7 `POST /v2/commands` (phone)

```json
{"id": "cHFyc3R1dnd4eXp7fH1-fw", "sealed": "..."}
```

`sealed` at most 8192 base64 characters. The command is queued and handed to every live stream of a
Mac in the group:

```json
{"status": "delivered", "delivered": true, "cursor": 7}
{"status": "queued", "delivered": false, "cursor": 7}
```

`delivered: true` means a Mac stream took the frame (it may still fail to execute it; wait for the
`result`). `queued` means no Mac is online: show "Mac offline, queued". Queued commands expire after
1 h. A repeated id returns `{"status":"duplicate","delivered":false,...}`. `429 queue_full` when 200
commands are pending, `429 rate_limited` above the per-group limit (default 1/s, burst 20).

### 6.8 `GET /v2/commands?since=<cursor>` and `POST /v2/commands/ack` (Mac)

Poll fallback when the WebSocket is not available:

```json
{"commands": [{"cursor": 7, "id": "...", "sealed": "...", "received_at": 1700000000}], "cursor": 7, "more": false}
```

`POST /v2/commands/ack` with `{"cursor": 7}` removes that command: `{"removed": true}` (false if it
was already gone). A Mac MUST ack a command after it has executed it (or decided not to) and sent the
result.

### 6.9 Other routes

- `GET /healthz`: `200 ok`.
- `GET /v2/debug/pushes`: only with `APNS_MODE=mock`; the recorded pushes. Unauthenticated, for local
  development only.
- `POST /v2/gateway/push`: only with `MODE=hosted`, section 9.

## 7. Stream: `GET /v2/stream` (Mac)

A WebSocket (RFC 6455) upgrade signed like any GET (`string_to_sign` with target `/v2/stream`, empty
body, the Mac's `device_id`). `URLSessionWebSocketTask` with a `URLRequest` carrying the four headers
works. Only Macs may connect; one stream per device: a new connection closes the previous one
(close code 1000, reason `replaced`).

Server to Mac, text frames:

```json
{"type": "command", "id": "...", "sealed": "...", "cursor": 7}
{"type": "ready"}
```

On connect the server first sends every queued command (backlog), then `ready`. After `ready`, new
commands arrive as they are posted. The same command can arrive more than once (backlog and live,
reconnects, several Macs): dedupe by `id` (section 4.4).

Mac to server, text frames:

- `{"type": "ack", "cursor": 7}`: same effect as section 6.8.
- `{"type": "bye", "reason": "quit"}`: the Mac is going offline on purpose; `reason` is `quit` (the
  app is quitting), `sleep` (the Mac is going to sleep) or `disabled` (the user turned Phone & Watch
  off). The server closes the stream (1000, `bye`) and announces the Mac offline at once
  (section 7a). Macs SHOULD send it, best effort, before they disconnect on purpose.

Any other frame closes the stream with 1008 (binary: 1003). Frames are limited to 4 KB.

Keepalive: the server sends a WebSocket ping every 30 s (`WS_PING_SECS`) and closes the stream (1001,
`idle`) after 65 s without any frame or pong from the Mac. Clients SHOULD reconnect with backoff
(1, 2, 4 ... 60 s) and fall back to polling section 6.8 every 30 to 60 s while the stream is down.

## 7a. Presence

The server tells the group's phones when alerts stop reaching them because no Mac is connected.

- When the group's **last** Mac stream ends after a `bye`, the server pushes an offline notice
  immediately. When it ends without one (network loss, crash, idle timeout), it waits
  `MAC_OFFLINE_GRACE_SECS` (default 120 s); if any Mac of the group reconnects in that time, nothing
  is sent (reconnects and flapping within the grace period are silent).
- When a Mac connects after an offline notice was sent, the server pushes a "back online" notice
  with the same `apns-collapse-id`, so it replaces the offline one.
- The server never sends the same state twice in a row, and never announces a Mac's first connect.
  The state is kept in memory: after a server restart nothing is pending and a reconnecting Mac is
  not announced.

APNs payload (built by the server; `apns-collapse-id: mc-presence`, `apns-expiration` = now + 1 h,
`apns-priority` 10 offline / 5 back online):

```json
{"aps": {"alert": {"title": "MetricCupid is offline on your Mac",
                   "body": "MetricCupid was quit. Alerts won't reach this iPhone until it's back."},
         "category": "MC_PRESENCE", "thread-id": "mc-presence", "sound": "default",
         "interruption-level": "time-sensitive"},
 "mc_presence": {"state": "offline", "reason": "quit", "since": 1700000000}}

{"aps": {"alert": {"title": "MetricCupid is back online",
                   "body": "Alerts from your Mac reach this iPhone again."},
         "category": "MC_PRESENCE", "thread-id": "mc-presence", "interruption-level": "passive"},
 "mc_presence": {"state": "online", "since": 1700000600}}
```

| `reason` | `body` |
|---|---|
| `quit` | MetricCupid was quit. Alerts won't reach this iPhone until it's back. |
| `sleep` | Your Mac went to sleep. Alerts won't reach this iPhone until it wakes. |
| `disabled` | Phone & Watch was turned off on the Mac. Alerts won't reach this iPhone until it's back on. |
| `lost` | The connection to your Mac was lost. Alerts won't reach this iPhone until it's back. |

`since` is the Unix time the server last heard from the Mac (offline) or the time it reconnected
(online). Presence payloads are **plaintext** and have no `mutable-content` and no `mc`: they carry
no alert content, only what the server already knows (section 10). The Notification Service
Extension is not invoked for them; if it is, it MUST pass a payload without `mc` through unchanged.
Phones SHOULD store the `mc_presence` state when they receive one (e.g. in the app group, for the
status header) and MUST NOT require them: `GET /v2/status` is the source of truth.

## 8. Delivery semantics summary

| Path | Guarantee |
|---|---|
| Mac to phone | APNs best effort; mailbox for 24 h as the source of truth |
| Phone to Mac | queued for 1 h until acked; at least once; Macs dedupe by id |
| Result | a normal message (`type: result`) with the alert's `collapse_id` |

## 9. Gateway (self-hosted server without its own APNs key)

APNs requires the provider key of the app's team, so a self-hosted server normally cannot push.
With `APNS_MODE=gateway` it forwards each push job to the hosted service (`GATEWAY_URL`, default
`https://push.metriccupid.sysop.cat`):

1. When the Mac creates the group on the self-hosted server, that server forwards the same
   `POST /v2/groups` body (`group_id`, `auth_key`, `licence`) to the gateway. A refusal by the gateway
   is returned to the Mac (`402`, `409`, `502`); the request is idempotent and can be retried.
2. Each push job is sent to the gateway:

```
POST /v2/gateway/push
X-MC-Timestamp, X-MC-Signature, X-MC-Group      (no X-MC-Device; device_id line empty)

{"device_token": "<hex>", "env": "production",
 "message": {"id": "<id>", "t": "alert", "s": "<sealed>"},
 "urgency": "critical", "collapse_id": "<optional>", "expiration": 1700003600}
```

A presence notice (section 7a) carries `"presence": {"state": "offline", "reason": "lost", "since":
1700000000}` instead of `message`; exactly one of the two is required (`400` otherwise).
`expiration` is 0 or at most 24 h ahead. The gateway builds the APNs payload itself from `message`
and `urgency` (section 6.5) or from `presence` (fixed texts, section 7a), so it cannot be used to
send arbitrary notification text, and sends it with its own key. A gateway older than this version
rejects `presence` (`400`): the self-hosted server then logs the failure and the phones get no
presence push (`GET /v2/status` still works). Answers: `200 {"status":"sent"}`, `410 {"error":"unregistered"}` (the self-hosted
server removes the token), `502 upstream_error`, `400`, `401`, `413`, `429` (per group, default
5/s, burst 50).

Privacy: the gateway learns the group id, `auth_key`, device tokens, ciphertext, sizes, urgency and
timing of pushes. It never sees `enc_key`, plaintext, device names or the mailbox, and stores
nothing but the group registration.

## 10. What the server sees

| Data | Visible to server |
|---|---|
| Alert, command and result contents | no (ciphertext) |
| `group_key`, `enc_key`, `collapse_key` | no |
| `auth_key` | yes (can authenticate as the group, cannot decrypt) |
| `group_id`, `device_id`, device kind and name, APNs tokens and environment | yes |
| Message and command ids, cursors, `collapse_id` (equality only) | yes |
| Timing, sizes, counts of messages and commands, which device sent them | yes |
| `urgency` (critical / normal / silent) and message `type` | yes: a documented leak needed for APNs priority, sound and category |
| Client IP addresses | yes (logged with the group id) |
| Whether and when each Mac is connected (`last_seen`), and why it disconnected (`bye` reason) | yes: the server uses it for presence pushes (section 7a), which are plaintext but contain nothing else |

A server operator, or anyone who obtains `auth_key`, can delete or withhold messages and inject
garbage that receivers drop, but cannot read or forge content.

## 11. Limits

| Limit | Default | Configurable |
|---|---|---|
| Clock skew | 300 s | no |
| Replay window | 600 s | no |
| Body | 16 KB (v1: 8 KB) | no |
| Devices per group | 10 | no |
| Mailbox | 24 h, 500 per group | no |
| Command queue | 1 h, 200 per group | no |
| Messages per group | 2/s, burst 60 | `RATE_V2_MESSAGES_*` |
| Commands per group | 1/s, burst 20 | `RATE_V2_COMMANDS_*` |
| Gateway pushes per group | 5/s, burst 50 | `RATE_V2_GATEWAY_*` |
| Group registrations per IP | 6/h, burst 3 | `RATE_V2_GROUPS_*` |
| Streams per server | 1024 | no |
| Mac offline grace (lost stream, no `bye`) | 120 s | `MAC_OFFLINE_GRACE_SECS` |
| Per-IP, global, auth-failure bans | as v1 | as v1 |

## 12. Error codes

`unauthorized` (401), `unknown_device`, `wrong_device_kind` (403), `not_found` (404),
`group_exists`, `device_limit` (409), `licence_required` (402), `payload_too_large` (413),
`rate_limited`, `queue_full` (429), `invalid_request` (400, with `detail`), `storage_error` (500),
`gateway_error`, `upstream_error` (502), `too_many_streams` (503).
