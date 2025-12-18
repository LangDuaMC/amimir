# amimir

a ~~micro~~ nanoservice to authorize mimir for tenancy

## config

- `TARGET_URL` (required): upstream Mimir (example: `http://mimir:8080`)
- `AUTH_SALT` / `AUTH_SALT_FILE` (required): random salt used to derive per-org keys (legacy: `PRIVATE_KEY` / `PRIVATE_KEY_FILE`)
- `ADMIN_KEY` / `ADMIN_KEY_FILE` (required): password for admin access (`admin:<ADMIN_KEY>`)
- `LISTEN_ADDR` (optional): default `0.0.0.0:3000`

## deploy (stack example)

```yml
services:
  mimir:
    image: grafana/mimir:latest
    ports:
      - "8080"
  amimir:
    image: ghcr.io/langduamc/amimir:main
    environment:
      TARGET_URL=http://mimir:8080
      AUTH_SALT="<random string>" # keep secret
      ADMIN_KEY="<random string>" # keep secret
    ports:
      - "3000"
```

## usage

Requests must include:
- `xorgid` (or `x-orgid` / `x-scope-orgid`) header
- HTTP Basic auth: `username = orgid`, `password = sha256_hex(AUTH_SALT + ":" + orgid)`

Generate a key via the admin UI:
- `GET /admin` (Basic auth required: `admin:<ADMIN_KEY>`)

Or via the admin API:
- `GET /admin/sign?orgid=<orgid>` (Basic auth required: `admin:<ADMIN_KEY>`)

```sh
curl -u "admin:${ADMIN_KEY}" "http://amimir:3000/admin/sign?orgid=tenant_123456"
```

prometheus config:

```yml
remote_write:
  - url: "http://amimir:3000/api/v1/push"
    headers:
      xorgid: tenant_123456
    basic_auth:
      username: tenant_123456
      password: <password>
```
