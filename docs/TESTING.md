# Test record and reproduction

Executed on 16 October 2026. Containerized WordPress **7.1.3**, PHP **8.3.35**, MariaDB **11.4**, and Caddy **2.10**. Browser: headless Chrome **153** through Playwright **1.56.1**. The same WordPress version was converted to a real multisite network for isolation tests. The host has Podman 5.7 / podman-compose 1.5; the Docker-compatible Compose file was used. PHP 8.1 is the declared minimum; the shipped code was executed on PHP 8.3, not every supported PHP/WordPress combination.

**SOCA 0.0.1 baseline:** The 27-group protocol suite and 18-group WordPress suite cover the initial release. The saved result in [TEST-RESULTS.txt](TEST-RESULTS.txt) records the exact checks run for this branch. Earlier development used an isolated WordPress installation and mock browser/provider tests; those results are not a claim of certification or live RESOAuth login.

## Suites

| Suite | Coverage |
| --- | --- |
| `tests/protocol.php` | PKCE published vector; strict encodings; proxy templates, exact client ID and metadata; private material rejection; public-address filtering; HTTP cache bounds; deny/allow precedence, exact domains and normalization; local redirects; discovery capability refusal; encryption/tampering/thumbprints/assertions; delayed weekly rollover and immutable retirement deadlines; unpublished active key refusal; ES256 and RS256 signatures; issuer/audience/azp/nonce/time/hash/header checks; client/provider key separation; controlled JWKS refresh; token exchange and UserInfo subject binding; URL query injection protection. |
| `tests/wordpress.php` | Real tables and non-autoloaded encrypted keys; public/local activation defaults; allow-any saves with preserved hidden allowlists and deny precedence; inline saved access-rule explanation and section anchor; renamed callback hook and absent profile panel; browser-bound atomic transactions/expiry; verified-email matching for ordinary and administrator accounts; changed-email stability; pairwise-subject relink refusal; registration gating/Subscriber-only creation; ambiguous emails; existing capabilities; scoped unlink; audit/public-document redaction. |
| `tests/concurrency.py` | Two independent PHP/WordPress processes race on one callback and on one account creation. Exactly one transaction consumer; exactly one user and identity. |
| `tests/browser.cjs` | Real HTTPS browser/WordPress requests with a synthetic provider transport. Full authorization/code/assertion/PKCE/ID-token/session flow, replay, bad nonce/issuer/time, unverified email, cancellation, automatic mode, local recovery/password flow, redirect confinement, admin UI/bulk input, public-document validation, test login preserving admin session, absence of profile identity controls, and logout avoiding loops. |
| `tests/multisite.php` | Independent settings, keys, encryption contexts, transactions and identities; nonmember refusal; separate binding on each site; site removal without affecting another site's identity; network deletion cleanup and network spam-account refusal. |

Synthetic profiles use actual OpenSSL-generated signing keys and real JWT signatures. The mock token endpoint checks code/client/redirect binding, S256 proof and the signed client assertion. It is not a fake boolean "login passed" hook. Outbound HTTP responses are supplied at the explicit trusted `oauth_cimd_auth_http` test boundary; this does **not** claim full native-transport coverage for every network fault. Native transport was additionally used to fetch live RESOAuth discovery successfully, and public documents were fetched over the running WordPress HTTPS server. Syntax checks and Composer advisory audit also passed.

Full live RESOAuth end-user interoperability, real pairwise-subject changes, provider cache behavior, automatic mirror infrastructure, independent penetration testing and OpenID certification remain unverified. Site Health checks describe maintenance/publication status; they are not certification.

## Fast protocol suite

```sh
php tests/protocol.php
# No host PHP required:
podman run --rm -v "$PWD:/app:ro" -w /app docker.io/library/php:8.3-cli php tests/protocol.php
```

The unit bootstrap supplies only the WordPress functions needed for isolated protocol tests. Real storage/session/account behavior is covered separately.

## Disposable WordPress suite

Use a fresh local Compose installation, never a production database. `tests/wordpress.php` creates/removes its own test users but still requires `WP_ENVIRONMENT_TYPE=local`. Test fixtures deliberately use synthetic keys and fixed local credentials. These files are **outside** the installable plugin ZIP.

```sh
podman compose -p ocimd-local up -d
mkdir -p work
curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o work/wp-cli.phar
podman cp work/wp-cli.phar ocimd-local_wordpress_1:/tmp/wp-cli.phar
podman exec -u www-data ocimd-local_wordpress_1 php /tmp/wp-cli.phar core install \
  --url=https://localhost:8443 --title='OAuth CIMD Test' \
  --admin_user=localadmin --admin_password='Local-fixture-password-749!' \
  --admin_email=admin@company.com --skip-email
podman exec -u www-data ocimd-local_wordpress_1 php /tmp/wp-cli.phar plugin activate simple-oauth-cimd-access
podman cp tests ocimd-local_wordpress_1:/tmp/tests
podman exec -u www-data ocimd-local_wordpress_1 php /tmp/wp-cli.phar eval-file /tmp/tests/wordpress.php
python3 tests/concurrency.py
```

`tests/concurrency.py` accepts `CONTAINER_ENGINE` (default `podman`) and `OCIMD_CONTAINER` (default `ocimd-local_wordpress_1`). Docker Compose commonly uses hyphens in container names; set the container variable accordingly. The fixed fixture password is published intentionally and must only be used in this loopback-only disposable installation.

## Browser suite

After the disposable WordPress installation above:

```sh
podman exec ocimd-local_wordpress_1 mkdir -p /var/www/html/wp-content/mu-plugins
podman cp tests/mock-provider.php ocimd-local_wordpress_1:/var/www/html/wp-content/mu-plugins/ocimd-fixture.php
podman exec -u www-data ocimd-local_wordpress_1 php /tmp/wp-cli.phar config set OCIMD_TEST_FIXTURES true --raw
podman exec -u www-data ocimd-local_wordpress_1 php /tmp/wp-cli.phar eval-file /tmp/tests/fixture-setup.php
podman cp tests/Caddyfile ocimd-local_https_1:/tmp/test-Caddyfile
podman exec ocimd-local_https_1 caddy reload --config /tmp/test-Caddyfile --adapter caddyfile
npm install --prefix work/browser --no-audit --no-fund playwright@1.56.1
PLAYWRIGHT_PATH="$PWD/work/browser/node_modules/playwright" node tests/browser.cjs
```

Set `CHROME_PATH` if Chrome is not `/usr/bin/google-chrome`. This **test browser only** ignores the disposable development certificate and maps the synthetic provider hostname to 127.0.0.1. Production plugin HTTPS verification is never disabled. The fixture transport runs only with both `OCIMD_TEST_FIXTURES=true` and a local environment. A full-page settings screenshot is saved under `work/` for inspection. Reset the fixture scenario and rate-limit transients between repeated browser runs if required. For a fresh run, remove test-created accounts or use a fresh database.

Remove the test MU plugin and test constant, restore normal settings and reload `tools/Caddyfile` before using the installation for anything else. The simplest reliable cleanup of this **disposable** test project is `podman compose -p ocimd-local down --volumes` after stopping any additional test containers. Do not run that against a project whose data you want to keep.

## Multisite suite

Create a separate disposable WordPress database/container with the same plugin mounted and `WP_ENVIRONMENT_TYPE=local`. Install it at `https://network.company.com`, then:

```sh
wp core multisite-convert --title='OAuth CIMD Network'
wp plugin activate simple-oauth-cimd-access --network
wp eval-file /path/to/tests/multisite.php
```

The test uses a second `/second/` site, validates both site-local and network deletion behavior, and removes its temporary site/user. It does not require public DNS, an external provider, or incoming network access.

## Release verification

```sh
composer audit --locked
find simple-oauth-cimd-access -name '*.php' -print0 | xargs -0 -n1 php -l
python3 tools/build.py
```

The build produces a single-folder WordPress plugin ZIP, a separate source ZIP containing Compose/tests/docs, and SHA-256 checksums. The plugin ZIP includes only production PHP/assets, the namespace-isolated JWT dependency, licenses and documentation/public evidence. No test provider, private key, database, browser profile, token, wp-config or scratch output is packaged. `tools/vendor.py` checks the pinned dependency archive SHA-256 before copying source and changing its namespace.
