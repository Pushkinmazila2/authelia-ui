# authelia-ui

Minimalistic, ultra-fast, zero-JS engineering console for [Authelia](https://www.authelia.com/) under 10 MB, built with Go (`scratch` image, pure Go SQLite without CGO).

## Key Features
- **Zero JavaScript (Pure HTML)**: Standard HTML forms and tables, instant loading, works in any browser, zero external CDN dependencies.
- **Single Multi-Purpose Binary**:
  - **UI Mode (default)**: Web management interface for `configuration.yml`, `users_database.yml`, and `db.sqlite3`.
  - **Guard Mode (`guard`)**: Secure Docker proxy (Stargate Guard) that restricts access to the Docker socket, controlling only the Authelia container and discovering host mount paths.
- **User Management**: Direct edit of `users_database.yml`, automatic standard Authelia Argon2id hashing (`$argon2id$v=19$m=65536,t=3,p=4$...`), group management, disable/enable and delete users.
- **Access Control Rules**: Top-to-bottom rule list in `configuration.yml`, up/down priority ordering, policy selection (`bypass`, `one_factor`, `two_factor`, `deny`), and resource regex rules.
- **SQLite Session Inspection**: Direct inspection of active sessions in `db.sqlite3` with one-click termination.
- **Security Diagnostics**: JWT secret strength, storage encryption key strength, TLS status, and recent `notification.txt` file contents.

## Docker Compose Setup

Run `authelia-ui` alongside Authelia with the isolated Docker Guard proxy:

```yaml
version: '3.8'

services:
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    restart: unless-stopped
    volumes:
      - ./config:/config
    ports:
      - "9091:9091"

  # Guard proxy: accesses docker socket, exposes restricted API for Authelia container
  authelia-guard:
    image: ghcr.io/pushkinmazila2/authelia-ui:latest
    container_name: authelia-guard
    restart: unless-stopped
    command: ["guard"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - LISTEN_ADDR=:2375
      - AUTHELIA_CONTAINER_NAME=authelia
    expose:
      - "2375"

  # UI console: pure HTML, accesses /config, talks to guard over internal network
  authelia-ui:
    image: ghcr.io/pushkinmazila2/authelia-ui:latest
    container_name: authelia-ui
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./config:/config:rw
    environment:
      - LISTEN_ADDR=:8080
      - CONFIG_PATH=/config/configuration.yml
      - USERS_PATH=/config/users_database.yml
      - NOTIFICATION_PATH=/config/notification.txt
      - DB_PATH=/config/db.sqlite3
      - GUARD_URL=http://authelia-guard:2375
    depends_on:
      - authelia-guard
      - authelia
```

## Environment Variables

| Variable | Default | Mode | Description |
|---|---|---|---|
| `MODE` | `ui` | Any | Set to `guard` to run in Docker Guard proxy mode |
| `LISTEN_ADDR` | `:8080` (or `:2375` for guard) | Any | HTTP listen address |
| `GUARD_URL` | empty | UI | URL to `authelia-guard` for container control & host path discovery |
| `CONFIG_PATH` | `/config/configuration.yml` | UI | Path to Authelia configuration |
| `USERS_PATH` | `/config/users_database.yml` | UI | Path to Authelia YAML file-based users database |
| `DB_PATH` | `/config/db.sqlite3` | UI | Path to SQLite session database |
| `NOTIFICATION_PATH` | `/config/notification.txt` | UI | Path to filesystem notifier file |
| `AUTHELIA_CONTAINER_NAME` | `authelia` | Guard | Name of target Authelia container to control |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Guard | Path to Docker UNIX domain socket |


