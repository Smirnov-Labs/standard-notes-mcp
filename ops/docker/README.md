# Test target: self-hosted `standardnotes/server` (V2)

A disposable, offline Standard Notes server used as the integration-test target
for this repo. It runs the open-source syncing-server, so **sync + conflict
handling behave exactly like the Proton-hosted cloud** — which is what the
write-safety tests exercise.

## Stand it up

```bash
mkdir -p ~/sn-test-server && cd ~/sn-test-server
curl -fsSL https://raw.githubusercontent.com/standardnotes/server/main/.env.sample > .env
# Fill the 3 required secrets in .env, one `openssl rand -hex 32` each:
#   AUTH_JWT_SECRET= AUTH_SERVER_ENCRYPTION_SERVER_KEY= VALET_TOKEN_SECRET=
curl -fsSL https://raw.githubusercontent.com/standardnotes/server/main/docker/localstack_bootstrap.sh > localstack_bootstrap.sh && chmod +x localstack_bootstrap.sh
curl -fsSL https://raw.githubusercontent.com/standardnotes/server/main/docker-compose.example.yml > docker-compose.yml
docker compose pull && docker compose up -d
```

Four containers come up: `server` (api-gateway + auth + sync + files, monolith),
`db` (mysql:8), `cache` (redis), `localstack` (SNS/SQS emulation). All images are
arm64-native on Apple Silicon — no Rosetta.

## Use it

- **Client endpoint:** `http://localhost:3000` — auth and sync are the **same**
  origin. Plain HTTP on localhost; no TLS, no cert dance.
- **Health:** `curl http://localhost:3000/healthcheck` → `OK`.
- **Accounts:** the Go test harness (`internal/testsupport`) registers throwaway
  004 accounts against this endpoint; `go test ./...` skips cleanly when it is
  down (or set `SN_TEST_SERVER=off`).

## What this CANNOT rehearse (needs the real-account canary)

- **Nested-tag rendering** — a client-/subscription-gated feature; whether a
  `cleanup/merged-source` tag shows as nested in the official app can only be
  checked on a real account.
- **Note-history retention** — a paid cloud feature; the free self-host gives
  little/none.
- **Rate limiting / 429s** — the cloud sits behind Cloudflare + app throttles;
  this stack has none.

## Teardown (disposable)

```bash
cd ~/sn-test-server && docker compose down -v && /bin/rm -rf data logs uploads
```

Server license: GPL-3.0 (we only talk to it over HTTP; it is not linked into this repo).
