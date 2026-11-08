# MetricCupid Push Relay

A small, self-hostable HTTP relay between the [MetricCupid](https://github.com/dzaczek) macOS app and
the [Pushover](https://pushover.net) API.

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
message naming the variable (secret values are never printed).

| Variable | Default | Description |
|---|---|---|
| `PUSHOVER_APP_TOKEN` | required | Pushover application API token. |
| `PUSHOVER_USER_KEY` | required | Pushover user or group key. |
| `RELAY_SECRETS` | required | Comma-separated HMAC secrets, each at least 32 characters. Any of them is accepted, so you can rotate without downtime (add new, update clients, remove old). |
| `BIND` | `0.0.0.0:8080` | Listen address. |
| `TRUST_PROXY` | `none` | How to find the client IP: `none` (TCP peer), `cloudflare`, or `xff:<cidr>[,<cidr>...]`. See [Client IP](#client-ip). |
| `CF_REFRESH` | `false` | With `cloudflare`: fetch `cloudflare.com/ips-v4` and `ips-v6` at startup; on any error the built-in list is used. |
| `CF_IPS_EXTRA` | empty | With `cloudflare`: extra CIDRs trusted to send `CF-Connecting-IP` (e.g. the cloudflared container network). |
| `MODE` | `selfhosted` | `selfhosted` or `hosted`. `hosted` is a placeholder for the future Pro service and returns `501`. |
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
  `not (http.request.uri.path in {"/v1/notify" "/healthz"})`
  or `(http.request.uri.path eq "/v1/notify" and http.request.method ne "POST")`
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
- **Resource limits**: 8 KB body, 10 s request timeout, 64 concurrent requests, 8 s upstream timeout,
  Compose limits of 64 MB RAM and 0.5 CPU.
- **Logging**: status, client IP, latency and an outcome label only. Secrets, the Pushover token/user
  key and message contents are never logged.
- **Container**: static binary on `distroless/static:nonroot`, no shell, read-only root, all
  capabilities dropped, `no-new-privileges`. TLS roots are compiled in (rustls + webpki-roots); no
  OpenSSL.
- **Message privacy**: alert contents pass through the relay and Pushover. Run the relay yourself if
  that matters to you.
- **Not covered**: volumetric DDoS against an exposed origin (use Cloudflare / a Tunnel), a
  compromised relay secret (rotate it via `RELAY_SECRETS`), a client whose clock is off by more than
  5 minutes.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## MetricCupid setup

In MetricCupid (DevOps mode): **Settings -> Notifications & Popups -> Pushover -> Relay**.

- **Relay URL**: e.g. `https://push.example.com` (the app appends `/v1/notify`).
- **Secret**: one of the values in `RELAY_SECRETS`. It is stored in the macOS Keychain.
- Press **Send test**.

In relay mode the Pushover token and user key are not needed on the Mac.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # unit tests + tests/api.rs (wiremock stands in for Pushover)
```

## Roadmap

- **Hosted Pro mode** (`MODE=hosted`): a relay run by the author for MetricCupid Pro subscribers,
  with licences checked via App Store signed transactions (JWS) and per-licence quotas. Today it only
  returns `501`.
- "Minimal content" option (send only severity and host).
- Server-side alert polling, so notifications arrive while the Mac sleeps.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
