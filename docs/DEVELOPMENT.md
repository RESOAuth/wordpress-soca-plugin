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

## PHP security scanning

`.github/workflows/php-security.yml` runs Psalm taint analysis, WordPressCS security sniffs through PHP_CodeSniffer, and Semgrep Community Edition on pull requests, pushes to `main`, weekly, and on manual dispatch. Findings fail the respective job. Scanner output stays in the Actions logs; no scanner account, API token, hosted analysis service, remote ruleset, or report upload is used. Image builds and dependency installation need network access; all fixture checks and production scans run in containers with `--network none` and a read-only repository mount.

Run the same checks locally from the repository root:

```sh
docker build -t soca-security-php tools/security
docker run --rm -v "$PWD:/app" -w /app/tools/security soca-security-php \
  composer install --no-interaction --prefer-dist --no-progress
docker run --rm --network none -v "$PWD:/app:ro" -w /app soca-security-php \
  sh tools/security/run.sh psalm
docker run --rm --network none -v "$PWD:/app:ro" -w /app soca-security-php \
  sh tools/security/run.sh phpcs
docker build -t soca-security-semgrep tools/security/semgrep
docker run --rm --network none -v "$PWD:/src:ro" -w /src soca-security-semgrep \
  sh tools/security/run.sh semgrep
```

Podman works with the same commands. PHP tooling uses PHP 8.3; Psalm analyzes the plugin against its PHP 8.1 minimum. Development tools have their own Composer manifest and lockfile under `tools/security`; they do not change the root runtime dependency inventory or the plugin's private dependency loader. Dependabot tracks these Composer packages and scanner container images. To update PHP scanner dependencies deliberately, run `composer update` in that directory using the PHP scanner container, then rerun all three checks.

The checks cover complementary cases:

- **Psalm** follows untrusted request data across files and through the plugin's actual `Support::scalar` wrapper. The WordPress plugin provides types; `PsalmTaintPlugin` loads additional taint models after those type stubs so `wp_unslash` and `sanitize_text_field` preserve taint, HTML escaping removes only HTML taints, HTTP response bodies are untrusted, and `wpdb` query arguments are SQL sinks. Both interpolated SQL and untrusted `prepare` templates are checked.
- **WordPressCS** checks output escaping, validated and sanitized input, nonce verification, prepared SQL, and placeholders. Existing public login and metadata flows have line-specific nonce exceptions with reasons: public callbacks use OAuth state, PKCE and ID-token validation; administrator settings still require a WordPress nonce. The JSON document output has a local HTML-taint exception because it is served as `application/json` with `nosniff`. There is no blanket baseline or disabled security category.
- **Semgrep CE** uses ten committed rule groups in `tools/security/semgrep/php.yml`: runtime PHP evaluation, shell execution, PHP deserialization, disabled TLS verification, weak hashes, request-controlled SQL, untrusted SQL templates, unescaped output, unsafe redirects, and request-controlled includes. It uses the open-source engine with metrics and update checks disabled. These are repository-maintained rules, not a mirror of Semgrep's hosted registry. CE does not provide cross-file analysis; Psalm supplies that complementary check. A local exception covers the login button helper whose URL and label are escaped internally.

Each scanner first checks deliberately unsafe and safe fixtures. Psalm's fixtures verify cross-file HTML, SQL and shell flows, input sanitization without output escaping, database-mode URL escaping, and untrusted HTTP bodies. WordPressCS verifies the core security sniffs and a safe nonce/escaping/prepared-SQL example. Semgrep tests positive and negative examples for every rule group. Fixture checks fail if expected vulnerabilities stop being detected. These files are analyzed only, never executed, and are excluded from the installable ZIP along with all scanner dependencies and configuration.

Extend taint models and fixtures when adding new WordPress wrappers or input/output paths. Static scans do not prove OAuth correctness or authorization policy; keep the protocol and WordPress integration suites in place.
