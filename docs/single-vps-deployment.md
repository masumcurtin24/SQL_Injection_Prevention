# Single-VPS production deployment

This runbook deploys the existing frontend and backend on one Linux VPS. Caddy
is the only public application entry point and automatically manages HTTPS.
The frontend's direct port is bound to `127.0.0.1`, while the backend remains
available only on the Compose network.

This is a first-public-demo configuration, not a high-availability design.
SQLite is appropriate only for modest traffic on one host. Automated spam
retraining and the spam autopipeline are disabled by default so a public demo
cannot silently change its active model.

## 1. Prepare the server and DNS

Install Git, Docker Engine, and the Docker Compose plugin on a supported Linux
VPS. The production override caps the backend at 3 GiB and the two proxy
containers at 256 MiB each, with a combined CPU ceiling of three cores. Use a
host with at least 4 GiB RAM (more if traffic or model workloads require it),
and monitor actual usage before committing to a provider size. Container JSON
logs rotate at 10 MiB and retain three files per service.

Create an `A` record for the deployment hostname pointing to the VPS public
IPv4 address. Add an `AAAA` record only if IPv6 is configured and reachable.
Caddy cannot obtain a public certificate until DNS resolves to this host.

At both the provider firewall and host firewall:

- allow SSH only from trusted administration addresses where practical;
- allow public TCP ports 80 and 443;
- allow public UDP port 443 if HTTP/3 is wanted; and
- do not allow public port 3000.

The production Compose override also enforces the port-3000 restriction by
binding it to loopback. Keep outbound DNS and HTTPS available for certificate
issuance and image downloads.

## 2. Configure secrets

Clone the repository on the VPS, enter its directory, and create the production
environment file:

```sh
cp docker/production.env.example .env.production
chmod 600 .env.production
```

Set `APP_DOMAIN` to the DNS name without `https://` or a path. Replace the admin
password and JWT secret. Generate a JWT secret without placing it in shell
history:

```sh
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Keep `.env.production` out of Git and back it up separately in encrypted secret
storage. Leave all three `PROD_*` automation switches set to `false` for the
initial public demo.

## 3. Validate and start

Every production command must use both Compose files and the production env
file:

```sh
docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml config --quiet

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml \
  up --detach --build

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml ps
```

After Caddy obtains a certificate, verify the public path:

```sh
curl --fail --show-error "https://YOUR_DOMAIN/health/ready"
```

Replace `YOUR_DOMAIN` with the configured hostname. Use `docker compose ...
logs --follow caddy frontend backend` with the same flags above to investigate
startup. Caddy access logging is not enabled, and Nginx logs normalized paths
without query strings or request bodies.

Caddy stores certificates and state in the `caddy-data` and `caddy-config`
named volumes. The application database lives in `backend-runtime`. Ordinary
`docker compose down` keeps all three volumes; do not add `--volumes` unless the
data is intentionally being destroyed.

## 4. Back up before each update

The database is SQLite, so stop the backend briefly to get a consistent volume
snapshot. The fixed Compose project name makes the database volume name
`sql-injection-prevention_backend-runtime`.

```sh
mkdir -p backups
chmod 700 backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml stop backend

docker volume inspect sql-injection-prevention_backend-runtime

docker run --rm \
  --mount type=volume,src=sql-injection-prevention_backend-runtime,dst=/source,readonly \
  --mount type=bind,src="$PWD/backups",dst=/backup \
  alpine:3.24.2 \
  tar -C /source -czf "/backup/backend-runtime-${STAMP}.tgz" .

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml start backend

sha256sum "backups/backend-runtime-${STAMP}.tgz" \
  > "backups/backend-runtime-${STAMP}.tgz.sha256"
```

Copy backups off the VPS and periodically test a restore on a non-production
host. Keep the matching Git commit ID and an encrypted copy of
`.env.production` with each release backup.

## 5. Update safely

Start from a clean working tree and record the currently deployed revision:

```sh
test -z "$(git status --porcelain)"
git rev-parse HEAD | tee backups/pre-update-commit.txt
git fetch --tags origin
git switch main
git pull --ff-only
```

Create the backup from the previous section, then validate, build, and replace
the services:

```sh
docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml config --quiet

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml build --pull

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml \
  up --detach --remove-orphans

curl --fail --show-error "https://YOUR_DOMAIN/health/ready"
```

Do not prune the previous images or delete the pre-update database backup until
the release has been observed under normal traffic.

## 6. Roll back

If the new release is unhealthy and its database migration is backward
compatible, return to the recorded commit and rebuild:

```sh
PREVIOUS_COMMIT="$(cat backups/pre-update-commit.txt)"
git switch --detach "$PREVIOUS_COMMIT"

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml \
  up --detach --build --remove-orphans
```

If the release changed the database incompatibly, restore its matching backup
as well. The following deliberately clears only the inspected application data
volume; set `ARCHIVE_NAME` to a file already in `$PWD/backups`:

```sh
ARCHIVE_NAME=backend-runtime-YYYYMMDDTHHMMSSZ.tgz
PREVIOUS_COMMIT="$(cat backups/pre-update-commit.txt)"
test -f "backups/$ARCHIVE_NAME"
sha256sum --check "backups/$ARCHIVE_NAME.sha256"
git switch --detach "$PREVIOUS_COMMIT"

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml down

docker volume inspect sql-injection-prevention_backend-runtime

docker run --rm \
  -e ARCHIVE_NAME="$ARCHIVE_NAME" \
  --mount type=volume,src=sql-injection-prevention_backend-runtime,dst=/target \
  --mount type=bind,src="$PWD/backups",dst=/backup,readonly \
  alpine:3.24.2 sh -ceu \
  'find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar -C /target -xzf "/backup/$ARCHIVE_NAME"'

docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.prod.yml \
  up --detach --build
```

Re-run the HTTPS health check and a login plus representative analysis request
after either rollback path. Return to the `main` branch only when intentionally
deploying a newer reviewed release.
