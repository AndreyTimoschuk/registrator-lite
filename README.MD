# Registrator-lite

**Registrator-Lite** is a small Go program in a Docker container.  
It watches your Docker containers and **adds** or **removes** their service data in **Consul** automatically.

---

## 1. Short description

* Runs in its own Docker container.  
* Watches Docker events.  
* When a container starts, it makes a **service** in Consul.  
* When a container stops, it deletes the service.  
* Works with normal bridge network and with `network_mode: host`.

---

## 2. Main features

| Feature | Simple words |
|---------|--------------|
| **Auto register / deregister** | Adds and removes services without human work. |
| **HTTP, TCP or TTL health checks** | You can check a URL, open a TCP port, or send TTL heartbeats. |
| **Many ports per container** | Use `SERVICE_<PORT>_*` to set many services in one container. |
| **Host-network support** | If the container uses host mode, the program reads the first `EXPOSE` port from the image. |
| **Container-name fallback** | If you do not set a name, the service name becomes the container name. |
| **Ignore rules** | Skip a whole container or only one port. |
| **Low memory** | Written in Go, one static binary. |

---

## 3. ENV and label settings

You can set them as **environment variables** or **Docker labels**.  
Replace `<PORT>` with the real port number (example: `8080`).

| Name | Value | Meaning |
|------|-------|---------|
| `SERVICE_IGNORE` | `true` | Skip the whole container. |
| `SERVICE_<PORT>_IGNORE` | `true` | Skip only this port. |
| `SERVICE_<PORT>_NAME` | text | Service name in Consul. |
| `SERVICE_<PORT>_ID` | text | Fixed ID (else auto). |
| `SERVICE_<PORT>_TAGS` | `tag1,tag2` | Comma list of tags. |
| `SERVICE_<PORT>_CHECK_HTTP` | `/path` | HTTP check path. |
| `SERVICE_<PORT>_TCP` | `true` | Use TCP check, not HTTP. |
| `SERVICE_<PORT>_TTL` | `15s` | TTL check time. |
| `SERVICE_<PORT>_CHECK_INTERVAL` | `10s` | Time between HTTP/TCP checks. |
| `SERVICE_<PORT>_CHECK_TIMEOUT` | `2s` | Timeout for HTTP/TCP checks. |
| `SERVICE_<PORT>_DEREG_AFTER` | `1m` | Remove service after this time in “critical” state. |
| `SERVICE_<PORT>` | *(only as label)* port number | Shortcut when you only need one port. |

### Global variables for Registrator container

| Name | Default | Meaning |
|------|---------|---------|
| `CONSUL_ADDR` | `consul:8500` | Where to send API calls. |
| `HOST_IP` | auto | Fixed host IP if auto guess is wrong. |
| `DEBUG` | unset | Set to `1` to print HTTP calls. |

---

## How to run

0. You need to have the Consul agent on the system as a systemd unit or container.
1. Build new version if neccessary.
2. Run docker container with registrator:

```sh
docker run -d --name registrator-lite \
  --network host \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CONSUL_ADDR=localhost:8500 \
  andrewka44/registrator-lite:latest
```
