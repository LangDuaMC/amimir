# amimir

a ~~micro~~ nanoservice to authorize mimir for tenancy

## deploy

stack:

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
      PRIVATE_KEY="<random string>" # please be inside .env
    ports:
      - "3000"
```

sign tenant:

```sh
docker compose exec amimir amimir-gen -u "tenant_123456"
```

prometheus config:

```yml
remote_write:
  - url: "http://amimir:3000/api/v1/push"
    basic_auth:
      username: tenant_123456
      password: <password>
```
