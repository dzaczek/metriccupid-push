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
Mac --POST /v2/messages (sealed summary)--> server mailbox --> iPhone app / widget read it when they run
Mac --POST /v2/snapshot (sealed, every active alert)--> server keeps the newest --> iPhone Active tab (GET /v2/snapshot)
Mac --POST /v2/activity-state (plaintext counts)--> server --APNs liveactivity--> Dynamic Island / Lock Screen
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
| `server_url` | e.g. `https://push-metriccupid.sysop.cat` (default) or a self-hosted URL, no trailing slash |

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

`type` is `alert`, `result`, `summary`, `snapshot` or `command`; `id` is the message or command id sent next to
`sealed`.
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
| `display_name` | string, optional | human name of the host (Icinga host `display_name`, Zabbix visible name); receivers show it instead of `host` when present |
| `kind` | string, optional | `digest`, see below; absent for an ordinary alert |

**Digest.** To avoid a flood of pushes during an outage, a Mac MAY send the first few new alerts of a
burst one by one and then a single `alert` with `kind: "digest"` standing for the rest. Its
`alert_id` is `metriccupid:digest:<random>`, `host` is empty, `severity` is the worst of the bundled
alerts, `state` is `firing`, `actions` is `["open"]`, `title` is e.g. `12 new alerts` and `summary`
e.g. `5 critical: web01, db02 and 3 more`, plus:

| Field | Type | Rule |
|---|---|---|
| `digest_count` | int | alerts bundled |
| `digest_critical` | int | of which critical |
| `digest_hosts` | array of string, at most 10 | distinct host (display) names, worst first |

Receivers that do not know `kind` show `title` and `summary` like any alert. The bundled alerts are
not sent individually; the Mac sends a later state change of one of them only if it escalates to
critical (then as an ordinary alert message). They are always in the `snapshot`.

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

`summary` (Mac to phones): the alerts that are active on the Mac right now, for the phone's widget.

| Field | Type | Rule |
|---|---|---|
| `critical`, `warning`, `unknown`, `info` | int | active (not muted) alerts per severity, after the Mac's source filters; `info` optional |
| `top` | array, at most 5 | newest active alerts, worst severity first: `{"alert_id", "severity", "host", "service" (optional), "title"}` |

The Mac sends a summary when the counts or `top` change (debounced, about 5 s) and every 15 min while
anything is active. Only the Mac that runs iPhone actions sends summaries. Receivers keep only the
summary with the highest `ts`.

`snapshot` (Mac to phones): every alert that is active or muted on the Mac right now, for the
phone's list of current alerts. Stored by the server (only the newest per group), never pushed, never
in the mailbox; read with `GET /v2/snapshot` (section 6.6a).

| Field | Type | Rule |
|---|---|---|
| `compressed` | bool | `true`: `items` is compressed as below |
| `count` | int | alerts on the Mac (can exceed the items sent, see `truncated`) |
| `truncated` | bool, optional | `true` when items were left out to fit the size limit |
| `items` | string | `base64( DEFLATE( UTF-8 JSON array of item ) )` |

Compression is **raw DEFLATE** (RFC 1951, no zlib header or checksum), which is what Apple's
`NSData.compressed(using: .zlib)` / `COMPRESSION_ZLIB` produce and consume. The compressed bytes are
base64-encoded inside the plaintext, so the plaintext stays JSON and the usual receiver rules (4.4)
apply unchanged; the plaintext is then sealed like every message (AAD `{group_id}|snapshot|{id}`).

Item, at most 2000, in the Mac's list order (worst severity first, newest first):

| Field | Type | Rule |
|---|---|---|
| `alert_id` | string | as in `alert` |
| `title` | string | at most 200 characters |
| `host` | string | host name at the source, may be empty |
| `display_name` | string, optional | human host name |
| `service` | string, optional | |
| `check` | string, optional | the check / rule that raised it (grouping "by alert") |
| `severity` | string | as in `alert` |
| `state` | string | `firing`, `acknowledged` or `muted` |
| `ack_by` | string, optional | |
| `muted_until` | int, optional | Unix seconds |
| `source` | string | as in `alert` |
| `source_name` | string, optional | the source's name on the Mac |
| `since` | int, optional | Unix time the alert started (or was first seen) |
| `summary` | string, optional | at most 200 characters |
| `url` | string, optional | as in `alert` |
| `actions` | array of string | as in `alert` |

Names are cut to 128 characters. The Mac sends a snapshot when the list changes (debounced about
5 s, at most one per 10 s) and every 5 min while linked, even when nothing changed, so a phone can
tell an old snapshot ("Mac offline?") from an empty list. Only the Mac that runs iPhone actions
sends snapshots. Receivers keep the snapshot with the highest `ts`.

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
`summary` first); the server answers `413 payload_too_large` otherwise. This limit is for pushed
messages; a `snapshot` (never pushed) has its own: `sealed` at most `V2_SNAPSHOT_MAX_BYTES` base64
characters (default 192 KB), so a plaintext of about 140 000 bytes.

## 5. Request authentication

### 5.1 Signature

Every v2 request except `POST /v2/groups` (creating a group) carries:

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

### 5.3 Client identification: `X-MC-Client`

Clients SHOULD send, on every v2 request (including `POST /v2/groups` and the `GET /v2/stream`
upgrade):

```
X-MC-Client: MetricCupid-Mac/1.33.0 (153)
X-MC-Client: MetricCupid-iOS/1.33.0 (6)
```

Format: `MetricCupid-<platform>/<marketing version> (<build>)`, at most 64 printable ASCII
characters; platforms `Mac`, `iOS`, `watchOS`. The header is informational only: it is **not**
signed, the server never makes a decision based on it, and a missing or malformed value is ignored
(not an error). The server records it per device for the operator's admin panel (section 10.1), so
the operator can see which app versions are still in use before changing the protocol.

## 6. HTTP API

All bodies are JSON (`Content-Type: application/json`), at most 16 KB (`413` above), except
`POST /v2/snapshot` (section 6.6a). Unknown
request fields are rejected with `400`. Errors are `{"error":"<code>"}`, validation errors add
`"detail"`. Rate-limited responses carry `Retry-After`.

Device-kind rules: "Mac" means a device registered with `kind: "mac"`, "phone" one with
`kind: "ios"`. Requests from a device that is not registered get `403 unknown_device`; from the wrong
kind, `403 wrong_device_kind`.

### 6.1 `POST /v2/groups` (unauthenticated)

```json
{"group_id": "EBESExQVFhcYGRobHB0eHw", "auth_key": "<base64 of the 32-byte auth_key>",
 "licence": {"kind": "app_transaction", "jws": "<AppTransaction.jwsRepresentation>"}}
```

`licence` is optional except on a hosted server in `LICENCE_MODE=app_transaction` (section 13); `jws`
at most 12 KB. `gateway: true` is set only by a self-hosted server forwarding the registration to its
gateway (section 9).

| Status | Body | Meaning |
|---|---|---|
| 201 | `{"status":"created","licence":{...} or null}` | `licence` as in `GET /v2/status`: null when none was attached |
| 200 | `{"status":"exists","licence":...}` | same id, same key: idempotent retry |
| 409 | `{"error":"group_exists"}` | same id, different key |
| 402 | `{"error":"licence_required"}` | hosted, `LICENCE_MODE=app_transaction`, no `licence` |
| 403 | `{"error":"licence_invalid","reason":"<code>"}` | the licence did not verify (section 13.3) |
| 403 | `{"error":"licence_in_use"}` | the purchase is already attached to `LICENCE_MAX_GROUPS` groups; the group is not created |
| 502 | `{"error":"gateway_error"}` | `APNS_MODE=gateway` and the gateway did not accept the registration; retry |
| 429 | `{"error":"rate_limited"}` | per-IP registration limit (default 6 per hour, burst 3) |

### 6.1a `DELETE /v2/groups` (Mac)

Deletes the caller's group with its devices, mailbox, command queue, Live Activity tokens and licence
attachment (which frees a slot for the purchase, section 13). Live streams of the group are closed.
`204`. The Mac SHOULD call it before it forgets a group secret ("Reset link").

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
 "macs": [{"device_id": "...", "online": false, "last_seen": 1700000000}],
 "licence": {"tier": "founder", "environment": "production", "verified_at": 1700000000},
 "licence_required": false, "licence_grace_until": null}
```

`licence` is the group's licence (section 13) or `null`. `licence_required` is true when the group
has none and the server refuses its messages and commands right now (`402`); `licence_grace_until` is
the end of the grace period (Unix seconds) on a server in `LICENCE_MODE=app_transaction` that has
one, else `null`. Self-hosted servers answer `null`, `false`, `null`.

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
| `type` | `alert`, `result` or `summary` |
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

A `summary` is stored but **never pushed** (`pushed: 0`): a visible notification per summary would be
noise, and silent background pushes are throttled by iOS. The server keeps only the group's newest
summary in the mailbox (storing one deletes the older ones), so summaries never push alerts out of it.

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
could not run. Retention: 24 h and at most 500 messages per group (oldest dropped). Snapshots are
never listed here (they have their own route, 6.6a), so a mailbox sync stays small.

### 6.6a `POST /v2/snapshot` (Mac) and `GET /v2/snapshot` (any device)

```json
{"id": "c25hcHNob3QtMDAwMDAwMQ", "sealed": "..."}
```

The body may be up to `V2_SNAPSHOT_MAX_BYTES` + 1 KB (other routes keep 16 KB); `sealed` longer than
`V2_SNAPSHOT_MAX_BYTES` (default 196 608) is `413 payload_too_large`. The server replaces the group's
stored snapshot and pushes nothing: `200 {"status":"stored"}`, or `{"status":"duplicate"}` if the
stored one already has this `id`. `429 rate_limited` above 1 per 5 s per group (burst 5); `402` as
for messages.

`GET /v2/snapshot` returns the stored snapshot, `ts` being when the server received it:

```json
{"id": "c25hcHNob3QtMDAwMDAwMQ", "ts": 1700000000, "sealed": "..."}
```

or `204` (no body) when the group has none (or it is older than 24 h). Phones SHOULD fetch it when
they come to the foreground, on pull-to-refresh and after a push while open; and SHOULD show a
snapshot whose plaintext `ts` is older than 15 min as possibly stale ("Mac offline?").

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
- Live Activity routes: section 6.10.
- `GET /v2/debug/pushes`: only with `APNS_MODE=mock`; the recorded pushes. Unauthenticated, for local
  development only.
- `POST /v2/gateway/push`: only with `MODE=hosted`, section 9.
- `PUT /v2/licence`: only with `MODE=hosted`, section 13.

### 6.10 Live Activity (Dynamic Island and Lock Screen)

The iPhone can show the group's alert counts in a Live Activity (`ActivityKit`, attributes type
`AlertsActivityAttributes`). iOS applies a Live Activity push itself: the Notification Service
Extension does not run, so **its content travels in plaintext** through the server and APNs. By
default it carries counts only. The Mac setting "Show host names on the lock screen (sent
unencrypted)", off by default, adds up to 4 short lines of host / service text (section 10).

#### `PUT /v2/activities/{device_id}` and `PUT /v2/activities/{device_id}/start-token` (phone)

`X-MC-Device` MUST equal `{device_id}`; phones only (`403 wrong_device_kind` otherwise).

```json
{"push_token": "<hex>", "apns_env": "sandbox", "started_at": 1700000000}
```

| Field | Rule |
|---|---|
| `push_token` | 64..=512 hex characters (stored lower case) |
| `apns_env` | `sandbox` or `production`; default `production` |
| `started_at` | optional, Unix seconds the activity started; default now, clamped to the last 8 h |

`/v2/activities/{device_id}` registers the push token of the phone's running activity
(`Activity.pushTokenUpdates`); a new token replaces the old one. `/start-token` registers the
push-to-start token (iOS 17.2+, `Activity.pushToStartTokenUpdates`). `201 {"status":"created"}`,
`200 {"status":"updated"}`. `DELETE` on either path removes the token: `204`, or `404 not_found`.
Phones MUST delete both when the user turns the activity off. Deleting the device removes them too.

#### `POST /v2/activity-state` (Mac)

```json
{"event": "update", "stale_secs": 2400,
 "state": {"critical": 2, "warning": 5, "unknown": 0, "mac_online": true,
           "lines": [{"severity": "critical", "text": "web01 · disk"}]}}
```

| Field | Rule |
|---|---|
| `event` | `update` or `end` |
| `state.critical`, `.warning`, `.unknown` | 0..=100000 |
| `state.mac_online` | optional, default `true` |
| `state.lines` | optional, at most 4 of `{"severity": "critical"/"warning"/"unknown"/"info", "text": 1..=40 characters, no control characters}`; only with the host names setting |
| `stale_secs` | optional, 60..=43200: `stale-date` = send time + `stale_secs` |

The server keeps the latest state per group (in memory) and pushes at most one Live Activity update
per group every 5 s: a state that arrives sooner is coalesced, and only the newest one is sent when
the 5 s have passed. `end` is never delayed. Answers: `200 {"status":"sent","pushed":1,"started":0,
"failed":0,"unregistered":0}` or `200 {"status":"coalesced","send_in":4}`; `429 rate_limited` above
one request per 5 s per group (burst 10). The Mac SHOULD send a state when the counts or lines change
(debounced, about 5 s), every 15 min while anything is active, and `end` when the user turns Phone &
Watch off. Only the Mac that runs iPhone actions sends states.

Push targets:

- `update` and `end` go to every registered activity token whose activity started less than 8 h
  ago (iOS ends activities after 8 h; older tokens are deleted). After an `end` the server deletes
  the group's activity tokens.
- With an `update` whose `critical` is above 0, a phone with a start token and no running activity
  gets an `event: "start"` push (push-to-start), at most once per 8 h per phone (the started
  activity may not get to register its token).
- When the Mac goes offline or comes back (section 7a), the latest state is sent again with
  `mac_online` false / true.

APNs request: `apns-push-type: liveactivity`, `apns-topic` = `APNS_TOPIC` +
`.push-type.liveactivity`, `apns-priority: 10` when the critical count went up since the last push
and for `start` and `end`, else `5`; `apns-expiration` = now + 1 h; no collapse id. Payload:

```json
{"aps": {"timestamp": 1700000005, "event": "update", "relevance-score": 100,
         "stale-date": 1700002405,
         "content-state": {"critical": 2, "warning": 5, "unknown": 0, "mac_online": true,
                           "updated_at": 1700000003,
                           "lines": [{"severity": "critical", "text": "web01 · disk"}]}}}
```

- `timestamp`: send time, strictly increasing per group (ActivityKit drops older pushes).
- `content-state.updated_at`: when the server received the state from the Mac; `lines` is omitted
  when empty. Swift: `ContentState` with snake_case `CodingKeys` and `updated_at` as Unix seconds
  (not `Date`, whose default `Codable` form is seconds since 2001).
- `relevance-score`: 100 if anything is critical, 50 if anything is a warning, else 10.
- `end` adds `"dismissal-date": <now>` and has no `stale-date`.
- `start` adds `"attributes-type": "AlertsActivityAttributes"`, `"attributes": {}` and
  `"alert": {"title": "MetricCupid", "body": "2 critical alerts"}` (fixed text, counts only).

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

The same two moments also re-send the group's latest Live Activity state with `mac_online: false` /
`true` (section 6.10), with the usual 5 s coalescing.

## 8. Delivery semantics summary

| Path | Guarantee |
|---|---|
| Mac to phone | APNs best effort; mailbox for 24 h as the source of truth |
| Phone to Mac | queued for 1 h until acked; at least once; Macs dedupe by id |
| Result | a normal message (`type: result`) with the alert's `collapse_id` |

## 9. Gateway (self-hosted server without its own APNs key)

APNs requires the provider key of the app's team, so a self-hosted server normally cannot push.
With `APNS_MODE=gateway` it forwards each push job to the hosted service (`GATEWAY_URL`, default
`https://push-metriccupid.sysop.cat`):

1. When the Mac creates the group on the self-hosted server, that server forwards the same
   `POST /v2/groups` body (`group_id`, `auth_key`, `licence` if any) to the gateway with
   `"gateway": true`. The gateway then requires no licence: self-hosting stays free. A refusal by the
   gateway is returned to the Mac (`402`, `403`, `409`, `502`); the request is idempotent and can be
   retried. A self-hosted server with licence support needs a gateway with licence support too (older
   gateways reject the `gateway` field with `400`).
2. Each push job is sent to the gateway:

```
POST /v2/gateway/push
X-MC-Timestamp, X-MC-Signature, X-MC-Group      (no X-MC-Device; device_id line empty)

{"device_token": "<hex>", "env": "production",
 "message": {"id": "<id>", "t": "alert", "s": "<sealed>"},
 "urgency": "critical", "collapse_id": "<optional>", "expiration": 1700003600}
```

A presence notice (section 7a) carries `"presence": {"state": "offline", "reason": "lost", "since":
1700000000}` instead of `message`. A Live Activity push (section 6.10) carries `"activity": {"event":
"update", "timestamp": 1700000005, "state": {<content-state>}, "stale_date": 1700002405,
"dismissal_date": <optional>}` with `device_token` = the activity token; the gateway validates the
state like `POST /v2/activity-state` (and its times within 24 h of now) and maps `urgency: "critical"`
to priority 10, anything else to 5. Exactly one of `message`, `presence` and `activity` is required
(`400` otherwise); a `message` with `t: "summary"` is refused (summaries are never pushed).
`expiration` is 0 or at most 24 h ahead. The gateway builds the APNs payload itself from `message`
and `urgency` (section 6.5) or from `presence` (fixed texts, section 7a), so it cannot be used to
send arbitrary notification text, and sends it with its own key. A gateway older than this version
rejects `presence` or `activity` (`400`): the self-hosted server then logs the failure and the phones
get no presence push (`GET /v2/status` still works) or no Live Activity update. Answers: `200 {"status":"sent"}`, `410 {"error":"unregistered"}` (the self-hosted
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
| Licence (hosted): App Store purchase id, environment, original purchase date, original app version and platform, when verified | yes, section 13.5 |
| Whether and when each Mac is connected (`last_seen`), and why it disconnected (`bye` reason) | yes: the server uses it for presence pushes (section 7a), which are plaintext but contain nothing else |
| `summary` contents | no (ciphertext; only that one was sent, and when) |
| `snapshot` contents | no (ciphertext; its size, which roughly tracks how many alerts are active, and when) |
| Live Activity state: counts of critical / warning / unknown alerts and their changes over time | **yes, plaintext** (section 6.10): ActivityKit applies it without the extension, so it cannot be encrypted. Also visible to APNs (Apple). |
| Live Activity lines (severity + host / service, up to 4 × 40 characters) | **yes, plaintext**, only if the user turns on "Show host names on the lock screen (sent unencrypted)" on the Mac (off by default) |
| Live Activity push tokens and start tokens, when each activity started | yes |

A server operator, or anyone who obtains `auth_key`, can delete or withhold messages and inject
garbage that receivers drop, but cannot read or forge content.

### 10.1 Operator metrics (admin panel)

When the operator enables the admin panel (`ADMIN_BIND`, README "Admin panel"), the server also
keeps operational metadata in its database. Without the panel nothing below is collected.

| Stored | Retention |
|---|---|
| Per request: time, route, HTTP status, outcome label, latency, request size, group and (signed) device id once authenticated, `X-MC-Client` (section 5.3), Cloudflare country (`CF-IPCountry`, only from a trusted proxy), and the client network truncated to **/24 (IPv4) or /48 (IPv6)** | raw rows `ADMIN_EVENTS_RETENTION_DAYS` (default 30) and at most 1 000 000 rows; successful polls (`GET /v2/messages`, `/v2/commands`, `/v2/status`, `/v2/devices`, `/v2/snapshot`) are only counted, not stored as rows |
| Per stored snapshot: kind `snapshot`, outcome (`stored`, `duplicate`) and the size of `sealed` | as above |
| Per push: type (`alert`, `result`, `presence`, `liveactivity`, `start`), outcome (`sent`, `failed`, `unregistered`), APNs status and reason, sender (`direct`, `gateway`, `mock`) and APNs environment | as above |
| WebSocket connect / disconnect with close reason and duration, presence transitions, licence verification outcomes (`ok` with tier / environment, `invalid` with reason, `in_use`), auth bans, admin logins | as above |
| Daily counters of all of the above per group, route, status, outcome and country | 400 days |
| Per device: first / last request time, last `X-MC-Client`, last country | until the group is deleted |

Never stored: full client IP addresses, message or command contents (they are ciphertext anyway),
APNs or activity tokens, the licence JWS or purchase id, request bodies.

## 11. Limits

| Limit | Default | Configurable |
|---|---|---|
| Clock skew | 300 s | no |
| Replay window | 600 s | no |
| Body | 16 KB (v1: 8 KB; snapshot: section 6.6a) | no |
| Devices per group | 10 | no |
| Mailbox | 24 h, 500 per group | no |
| Command queue | 1 h, 200 per group | no |
| Messages per group | 2/s, burst 60 | `RATE_V2_MESSAGES_*` |
| Commands per group | 1/s, burst 20 | `RATE_V2_COMMANDS_*` |
| Gateway pushes per group | 5/s, burst 50 | `RATE_V2_GATEWAY_*` |
| `POST /v2/activity-state` per group | 1 per 5 s, burst 10 | no |
| `POST /v2/snapshot` per group | 1 per 5 s, burst 5 | no |
| Snapshot `sealed` | 192 KB (196 608 base64 characters); body + 1 KB | `V2_SNAPSHOT_MAX_BYTES` |
| Live Activity pushes per group | at most 1 per 5 s (coalesced; `end` immediate) | no |
| Push-to-start per phone | 1 per 8 h | no |
| Group registrations per IP | 6/h, burst 3 | `RATE_V2_GROUPS_*` |
| Groups per App Store purchase (hosted) | 3 | `LICENCE_MAX_GROUPS` |
| Streams per server | 1024 | no |
| Mac offline grace (lost stream, no `bye`) | 120 s | `MAC_OFFLINE_GRACE_SECS` |
| Per-IP, global, auth-failure bans | as v1 | as v1 |

## 12. Error codes

`unauthorized` (401), `unknown_device`, `wrong_device_kind`, `licence_invalid` (with `reason`),
`licence_in_use` (403), `not_found` (404), `group_exists`, `device_limit` (409),
`licence_required` (402), `payload_too_large` (413),
`rate_limited`, `queue_full` (429), `invalid_request` (400, with `detail`), `storage_error` (500),
`gateway_error`, `upstream_error` (502), `too_many_streams` (503).

## 13. Licences (hosted service)

A self-hosted server never requires a licence. The hosted service (`MODE=hosted`) is included with
the purchase of the MetricCupid app ("model A"): a group needs proof that one of its users owns the
app. Today that proof is StoreKit 2's `AppTransaction`, and every such licence has tier `founder`.

### 13.1 Modes

| `LICENCE_MODE` | Behaviour |
|---|---|
| `open` | Any group may register and send. A `licence` in `POST /v2/groups` is verified and attached when valid, otherwise ignored; `PUT /v2/licence` works. `HOSTED_OPEN_REGISTRATION=true` is an alias. |
| `app_transaction` (hosted default) | `POST /v2/groups` needs a valid licence (`402` / `403`), except gateway registrations (section 9). Groups without one may authenticate, read (`GET` routes, `/v2/stream`, devices, acks) and attach one, but `POST /v2/messages`, `POST /v2/commands` and `POST /v2/activity-state` return `402 licence_required`. |

`LICENCE_GRACE_UNTIL` (RFC 3339 time or `YYYY-MM-DD`, UTC midnight) lets groups without a licence
keep sending until then, so groups created during the open beta keep working while their Macs update
and attach one. New groups need a licence during the grace period too.

### 13.2 Client flow

1. The Mac creates a group on the hosted server with `licence: {"kind": "app_transaction", "jws":
   AppTransaction.shared.jwsRepresentation}`. It MUST NOT send a licence to any other server.
2. Whenever `GET /v2/status` shows `licence: null` on the hosted server, the Mac attaches one:

```
PUT /v2/licence          (signed, any registered device)
{"kind": "app_transaction", "jws": "<AppTransaction.jwsRepresentation>"}
```

   `200 {"status": "attached" | "refreshed", "licence": {"tier", "environment", "verified_at"}}`, or
   the `403` answers of section 6.1. Attaching the same purchase again refreshes `verified_at`;
   another purchase replaces the group's licence.
3. On `402 licence_required` a sender MUST NOT retry the request: it SHOULD back off, show the
   problem once, and try again after attaching a licence. The iPhone app cannot attach one (it does
   not hold the Mac's purchase context); it SHOULD tell the user to open MetricCupid on the Mac.
4. Before forgetting a group, the Mac SHOULD `DELETE /v2/groups`, which frees the purchase's slot.

### 13.3 Verification

The server verifies the JWS as Apple's App Store Server Library does:

- compact JWS, header `alg: "ES256"` and `x5c` with exactly three certificates (leaf, intermediate,
  root);
- the root is byte-for-byte Apple Root CA - G3 (embedded in the server, SHA-256
  `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179`);
- each certificate is issued by the next (names and ECDSA signatures; Apple uses P-384 / SHA-384),
  the intermediate is a CA, all three are valid **at the payload's `signedDate`** (or
  `receiptCreationDate` if absent), not at the current time, so a later certificate rotation does
  not void old transactions;
- the leaf has extension `1.2.840.113635.100.6.11.1`, the intermediate `1.2.840.113635.100.6.2.1`;
- the JWS signature (P-256, SHA-256) verifies with the leaf key;
- payload: `bundleId` is `cat.sysop.MetricCupid`; `receiptType` is `Production`, or `Sandbox`
  (TestFlight) while `LICENCE_ALLOW_SANDBOX=true`; never `Xcode`; for `Production`, `appAppleId`, if
  present, is `6757280443` (StoreKit has been seen to omit it on real installs; bundle id and
  Apple's signature already identify the app).

`reason` codes of `403 licence_invalid`: `unsupported_kind`, `malformed`, `chain`, `untrusted_root`,
`certificate_expired`, `not_apple`, `signature`, `wrong_bundle`, `wrong_app`, `environment`. The JWS
is never echoed or logged. `deviceVerification` is not used: the same purchase is valid on every
device of the Apple ID.

### 13.4 Sharing limit

A purchase is identified by `appTransactionId`. If the payload has none (older OS versions), by
`sha256:` + hex SHA-256 of `"{originalPurchaseDate}|{appAppleId}|{originalPlatform}"` (missing values
as `0` / empty). One purchase may be attached to at most `LICENCE_MAX_GROUPS` (default 3) groups;
another group gets `403 licence_in_use`. All Macs and iPhones of one Apple ID normally share one group
(the group secret syncs through iCloud Keychain), so the limit is about separate setups. A slot is
freed by deleting a group (section 6.1a).

### 13.5 What is stored

Per group: licence kind (`app_transaction`), `tier`, environment (`production` / `sandbox`), the
purchase id of 13.4, `originalPurchaseDate`, `originalApplicationVersion`, `originalPlatform`, when it
was first attached and last verified. Not stored: the JWS, `deviceVerification`, the Apple ID or any
other payload field. Responses only ever contain `tier`, `environment` and `verified_at`. Deleting the
group deletes the row.

### 13.6 Tiers and the planned subscription model

Every licence verified under model A has tier `founder`. A later version may introduce a free tier
and subscriptions (`pro`, StoreKit `Transaction` JWS with an expiry). The migration keeps founders:

- groups whose stored tier is `founder` stay `founder`, without a subscription;
- a purchase whose `originalPurchaseDate` (or `originalApplicationVersion`) predates the switch keeps
  qualifying as `founder` when attached to a new group, because the `AppTransaction` of an earlier
  paid download still carries the original purchase;
- new kinds will be added to `licence.kind` (`app_transaction` stays valid); clients SHOULD show an
  unknown `tier` as "licensed" and MUST rely on `licence_required`, not on the tier, for behaviour.
