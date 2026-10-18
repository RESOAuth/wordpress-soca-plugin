# SOCA development and validation

## Local Docker setup

```sh
docker compose up -d
# Open https://localhost:8443 and finish the normal WordPress installer.
```

This starts a clean WordPress **7.1.3 / PHP 8.3**, MariaDB 11.4, and Caddy with a local certificate. Only HTTPS on loopback port 8443 is published; the database and plain HTTP WordPress service are private to the Compose network. The fixed database credentials are for this disposable local environment only. Install a trusted Caddy development CA before logging in:

```sh
mkdir -p work
docker compose cp https:/data/caddy/pki/authorities/local/root.crt work/local-ca.crt
# Import work/local-ca.crt into your development browser/OS trust store.
# Example command-line verification without changing system trust:
curl --cacert work/local-ca.crt https://localhost:8443/
```

Caddy's internal certificate is for the local browser, not a cloud provider. This web-client profile requires HTTPS even on localhost and never disables outbound TLS verification. If an upstream provider rejects a localhost redirect or does not support inline JWKS, use a genuinely public HTTPS tunnel/site and select self-hosted metadata, or use a stable public JWKS mirror with a provider-approved callback. A proxy cannot make localhost JWKS reachable.

The plugin directory is mounted into WordPress. Activate it in the dashboard, or use the optional CLI service after installation:

```sh
docker compose --profile tools run --rm --no-deps cli wp plugin activate simple-oauth-cimd-access
docker compose --profile tools run --rm --no-deps cli wp soca status
```

Use `podman compose` in place of `docker compose` if preferred; both use the supplied Compose file. To stop the local environment, run `docker compose down`. Add `--volumes` only when you intend to delete its WordPress and database contents.

## Build and validation

The plugin, repository tooling and documentation are AGPL-3.0-only (see the root and bundled plugin LICENSE files). The bundled php-jwt library retains its BSD-3-Clause license.

The implementation is plain PHP/WordPress with one runtime library: `firebase/php-jwt` **7.2.1**, pinned by commit, lockfile and archive digest, with only its namespace changed to avoid conflicts with other plugins. Review and update it deliberately using `python3 tools/vendor.py`; see `simple-oauth-cimd-access/vendor/VERSION.json`. `composer audit --locked` checks the dependency inventory; root Composer output is not the production loader.

```sh
php tests/protocol.php
# Or with a container:
docker run --rm -v "$PWD:/app:ro" -w /app php:8.3-cli php tests/protocol.php
python3 tools/build.py
```

[TESTING.md](TESTING.md) documents the real WordPress, concurrent-request, browser and multisite suites, exact tested profiles and limitations. Test fixtures live outside the installable plugin and must never be deployed to production. `tools/build.py` excludes all test fixtures, runtime databases, credentials and scratch work from release archives.
