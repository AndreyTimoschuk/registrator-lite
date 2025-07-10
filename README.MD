# Registrator-lite

**Registrator-Lite** is a small Go program in a Docker container.  
It watches your Docker containers and **adds** or **removes** their service data in **Consul** automatically.

---

## 1 · What it does

| Action | When it happens |
|--------|-----------------|
| **Register** service in Consul | When a container fires a `start` event (or is spotted during a periodic rescan). |
| **Keep health-checks** up | Optional HTTP / TCP or TTL checks per port. |
| **Send TTL heart-beats** | When a port is configured with `SERVICE_<PORT>_TTL`. |
| **Deregister** service | As soon as the container stops, or after Consul’s own `DEREG_AFTER`. |
| **Cleanup stale entries** | When `CLEANUP=true` — removes records whose container (CID tag) no longer exists on this host. |
| **Periodic resync** | Full `docker ps` + cleanup every `RESYNC` seconds (default 60 s, `0` = disabled). |

---

## 2 · Key features & quirks

| Feature | Details & tips |
|---------|----------------|
| **Multiple ports** | Describe each port with `SERVICE_<PORT>_*`. By default only the **first** port is registered; use `-all-ports` or `REGISTER_ALL_PORTS=true` to include the rest. |
| **Smart service names** | *If* you: **(a)** do **not** set `SERVICE_<PORT>_NAME`, **(b)** do **not** set `container_name`, and **(c)** run under Compose, the service name falls back to the pure Compose *service* (`app`), **not** the long auto-name (`project_app_1`). <br>Give a real `container_name:` and it wins. |
| **Internal mode** | `-internal` / `INTERNAL=true` ⇒ service is bound to the **container’s own IP** (not the host) and **all active checks are disabled** (makes sense in pure overlay networks or when Envoy / sidecar does its own health). |
| **Automatic meta-tags** | Unless disabled, every service receives<br>`managed-by=registrator-lite`, `node:<hostname>`, `cid:<12chars>`.  These guarantee cleanup never touches anything it didn’t create. |
| **Tag toggle** | Global → `-auto-tags=false` or `AUTO_TAGS=false`.<br>Per-container → `SERVICE_AUTO_TAGS=false`. |
| **Graceful Consul cleanup** | If tags are off the service is *invisible* to the cleanup routine — handy for hand-crafted or foreign entries. |
| **Minimum `DEREG_AFTER`** | Consul enforces ≥ 1 m. If you set `30s`, Consul accepts it but logs a warning and coerces it to 1 m. Registrator just passes your value through. |
| **Low footprint** | Single static binary; image is < 10 MB. |

---

## 3 · Per-port variables / labels

Replace `<PORT>` with the number (e.g. `8080`).

| Key | Example | Meaning |
|-----|---------|---------|
| `SERVICE_<PORT>_IGNORE` | `true` | Skip this port completely. |
| `SERVICE_<PORT>_NAME` | `web-v2` | Explicit service name. |
| `SERVICE_<PORT>_ID` | `web-v2-east` | Fixed Consul ID (else auto). |
| `SERVICE_<PORT>_TAGS` | `foo,bar` | Comma list of Consul tags. |
| `SERVICE_<PORT>_TCP` | `true` | Use TCP health check instead of HTTP. |
| `SERVICE_<PORT>_CHECK_HTTP` | `/health` | Relative URL for HTTP check. |
| `SERVICE_<PORT>_TTL` | `30s` | TTL style check; Registrator sends keep-alive at ¹⁄₃ TTL. |
| `SERVICE_<PORT>_CHECK_INTERVAL` | `5s` | HTTP/TCP check interval. |
| `SERVICE_<PORT>_CHECK_TIMEOUT` | `2s` | HTTP/TCP timeout. |
| `SERVICE_<PORT>_DEREG_AFTER` | `2m` | Let Consul auto-remove when critical that long. |
| Label shortcut: `service.<port>` | `8080` | Minimal case: only wrap this port; everything else defaults. |

---

## 4 · Container-level variables / labels

| Key | Default | Purpose |
|-----|---------|---------|
| `SERVICE_IGNORE` | — | Skip **entire** container. |
| `SERVICE_AUTO_TAGS` | inherit global | `false` → do not add the `managed-by/node/cid` trio for this container only. |
| `INTERNAL` | inherit global | Force internal mode for this one container. |

---

## 5 · Global environment / CLI flags

| Env / Flag | Default | Description |
|------------|---------|-------------|
| `CONSUL_ADDR`, `-consul` | `consul:8500` | Consul HTTP(S) endpoint. |
| `CONSUL_HTTP_TOKEN` | — | ACL token if needed. |
| `CONSUL_SKIP_VERIFY`, `-insecure` | `0` | `1` or flag → skip TLS cert verify. |
| `REGISTER_ALL_PORTS`, `-all-ports` | `false` | Register every port instead of first. |
| `INTERNAL`, `-internal` | `false` | Container IPs, no checks. |
| `AUTO_TAGS`, `-auto-tags` | `true` | Add `managed-by/node/cid` tags. |
| `CLEANUP`, `-cleanup` | `false` | Enable stale-service cleanup loop. |
| `RESYNC`, `-resync` | `60s` | Full docker-ps refresh; `0` disables. |
| `TTL`, `-ttl` | `0` | Default TTL if a port didn’t specify one. |
| `DEBUG` | `0` | `1` → verbose HTTP/Consul logs. |
| `HOST_IP` | auto | Fixed host IP if auto guess is wrong. |

---

## 6 · How cleanup works (safe & isolated)

1. Reads `/v1/agent/services` from local Consul.  
2. Keeps only services whose **tags contain all** of:  
   `managed-by=registrator-lite`, `node:<this-host>`, `cid:<cid>`.  
3. If `<cid>` is **not** in `docker ps`, deregisters the service.  
4. Anything without those tags (handmade services, other hosts,
   other tools) is left untouched.

Disable auto-tags → service is never considered by cleanup.

---

## How to run

0. You need to have the Consul agent on the system as a systemd unit or container.
1. Build new version if neccessary.
2. Or run docker container with registrator:

```sh
docker run -d --name registrator-lite \
  --network host \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CONSUL_ADDR=localhost:8500 \
  andrewka44/registrator-lite:latest
```
