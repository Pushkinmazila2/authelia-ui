# authelia-ui

Minimalistic, ultra-fast, zero-JS engineering console and headless REST API for [Authelia](https://www.authelia.com/) under 10 MB, built with Go (`scratch` image, pure Go SQLite without CGO).

## Attention
This project is for convenient testing only; it cannot be used in production!

## Operating Modes (`MODE`)
A single multi-purpose binary runs in three distinct modes:
1. **`ui` (default)**: Clean HTML-only console (Zero JavaScript) + embedded Bearer REST API. Protected with Login / Password.
2. **`api`**: Headless REST API mode without any HTML interface. All `/api/*` endpoints require Bearer Token authorization.
3. **`guard`**: Secure Docker proxy sidecar (Stargate Guard) with restricted access to `/var/run/docker.sock`, allowing only operations on the target Authelia container.

## Key Features
- **Zero JavaScript (Pure HTML)**: Standard semantic HTML forms and tables, instant loading, works in any browser, zero external CDN dependencies.
- **UI Authentication**: Built-in HTTP-only cookie authentication with HMAC signature configured via `UI_USER` and `UI_PASSWORD`.
- **API Token Authentication**: All `/api/*` endpoints protected via `Authorization: Bearer <API_TOKEN>` or `X-API-Key`.
- **User & Group Management**: Parse/edit `users_database.yml`, automatic standard Authelia Argon2id hashing (`$argon2id$v=19$m=65536,t=3,p=4$...`), group assignment, group rename and mass deletion across users.
- **OIDC / OAuth 2.0 Clients**: Manage `identity_providers.oidc.clients` in `configuration.yml` (ID, redirect URIs, scopes, authorization policy, and auto-generated hashed client secrets).
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

  # UI console (or API mode by setting MODE=api or command: ["api"])
  authelia-ui:
    image: ghcr.io/pushkinmazila2/authelia-ui:latest
    container_name: authelia-ui
    restart: unless-stopped
    ports:
      - "8383:8080"
    volumes:
      - ./config:/config:rw
    environment:
      - LISTEN_ADDR=:8080
      - CONFIG_PATH=/config/configuration.yml
      - USERS_PATH=/config/users_database.yml
      - NOTIFICATION_PATH=/config/notification.txt
      - DB_PATH=/config/db.sqlite3
      - GUARD_URL=http://authelia-guard:2375
      - UI_USER=admin
      - UI_PASSWORD=your_secure_password
      - API_TOKEN=your_secure_api_token
    depends_on:
      - authelia-guard
      - authelia
```

## REST API Reference (`MODE=api` or embedded in `ui`)

Send `Authorization: Bearer <API_TOKEN>` with all requests:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Authelia container & config diagnostics |
| `POST` | `/api/restart` | Restart Authelia container via Guard |
| `GET`, `POST` | `/api/users` | List users or create new user (auto Argon2id) |
| `GET`, `PUT`, `DELETE` | `/api/users/{username}` | Get, update, or delete user |
| `GET` | `/api/groups` | List all unique groups and their member list |
| `POST` | `/api/groups/add` | Add or assign group to users (`name`, `users`) |
| `POST` | `/api/groups/rename` | Rename group across all users (`old_name`, `new_name`) |
| `POST` | `/api/groups/delete` | Delete group from all users (`name`) |
| `GET`, `POST` | `/api/clients` | List OIDC clients or register new client |
| `GET`, `PUT`, `DELETE` | `/api/clients/{id}` | Inspect, update, or delete OIDC client |
| `GET`, `POST` | `/api/rules` | Read or append access control rules |
| `GET`, `PUT`, `DELETE` | `/api/rules/{index}` | Inspect, edit, or delete rule by index |
| `GET` | `/api/sessions` | Inspect active SQLite user sessions |
| `DELETE` | `/api/sessions/{key}` | Terminate specific user session |
| `GET` | `/api/logs` | Fetch Authelia container logs |

## Environment Variables

| Variable | Default | Mode | Description |
|---|---|---|---|
| `MODE` | `ui` | Any | Set to `ui`, `api`, or `guard` |
| `LISTEN_ADDR` | `:8080` (or `:2375` for guard) | Any | HTTP listen address |
| `UI_USER` | `""` | UI | Username for UI web console |
| `UI_PASSWORD` | `""` | UI | Password for UI web console (empty = auth disabled) |
| `SESSION_SECRET` | random | UI | Secret used for HMAC-signing auth cookies |
| `API_TOKEN` | `""` | API/UI | Bearer token required for all `/api/*` endpoints |
| `GUARD_URL` | empty | UI/API | URL to `authelia-guard` for container control & host path discovery |
| `CONFIG_PATH` | `/config/configuration.yml` | UI/API | Path to Authelia configuration |
| `USERS_PATH` | `/config/users_database.yml` | UI/API | Path to Authelia YAML file-based users database |
| `DB_PATH` | `/config/db.sqlite3` | UI/API | Path to SQLite session database |
| `NOTIFICATION_PATH` | `/config/notification.txt` | UI/API | Path to filesystem notifier file |
| `AUTHELIA_CONTAINER_NAME` | `authelia` | Guard | Name of target Authelia container to control |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Guard | Path to Docker UNIX domain socket |



