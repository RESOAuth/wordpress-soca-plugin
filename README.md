# SOCA - Simple OAuth CIMD Access for WordPress

SOCA (Simple OAuth CIMD Access) is an open-source WordPress single sign-on plugin built and supported by RESOAuth® that can use another compatible configured provider. It uses OIDC authorization code + PKCE S256, `private_key_jwt` ES256, and self-hosted or proxy Client ID Metadata Documents (CIMD). It does **not** make WordPress an authorization server.

Install `dist/simple-oauth-cimd-access-0.0.1.zip` using **Plugins → Add Plugin → Upload Plugin**, activate it, then open **Settings → SOCA**. PHP 8.1+, OpenSSL, cURL, and WordPress 6.8+ are required. The release contains its isolated JWT dependency; Composer is not needed on the WordPress server.

When upgrading from the old `oauth-cimd-auth` folder, install the new ZIP, deactivate **OAuth CIMD Auth**, then activate **SOCA**. Both folders must not run together. Existing site settings, encrypted keys and issuer/subject bindings are retained under their original internal database names; uninstalling the old plugin preserves them by default. The internal `OCIMD` PHP namespace and `ocimd_*` storage names remain for compatibility. Check the new client metadata URL and complete a fresh test login before removing the old folder.

## Setup

1. Keep a local administrator account and password. Bookmark `/wp-login.php?soca_local=1`. Confirm WordPress uses HTTPS and has unique authentication keys/salts in `wp-config.php`.
2. Review the issuer, provider name and button label. Initial settings use RESOAuth at `https://auth.resoauth.cloud`, scopes `openid email profile`, ES256 client authentication. Public HTTPS sites default to self-hosted CIMD and the derived JWKS URL, and show the login button on activation. Local sites select the supplied configurable proxy and inline public keys; their login button stays off until an admission rule is chosen.
3. Review admission rules. The suggested domain is the exact home hostname with one leading `www.` removed; localhost, IPs and reserved development names are excluded. Deny wins; either allowlist can admit. **Allow any verified email/domain** starts off and, when selected, hides the allowlists while keeping denylists active. Domains match exactly. First-login verified-email matching includes existing administrator accounts by default. Registration remains off; new accounts, when enabled, are Subscribers.
   On upgrade, a previously saved unrestricted flag is cleared when allowlists were populated, preserving the old effective policy until an administrator deliberately selects Allow any.
4. **Validate connection and documents → Test login.** The test keeps your current administrator session, validates a fresh upstream login and reports the saved email policy without creating/linking an account. Automatic redirect is optional.

The separate **Test access rules** form explains how the saved allowed/denied email and domain rules treat an address. It links back to Access rules, keeps the tested address visible, and shows the result beside the field and button. Unsaved edits are not included.

The advanced **Client assertion audience** setting defaults to the provider issuer for new installations. RESOAuth's token endpoint requires that value. Other providers may require the token endpoint URL; select it in advanced settings if their profile calls for it. Existing installations retain their previous token endpoint audience until changed. The selection is pinned in each login transaction and does not alter PKCE, signature checks or transport security.

Public routes use `?soca_doc=client` for self-hosted CIMD, `?soca_doc=jwks` for public keys, and `wp-admin/admin-post.php?action=soca_callback` for the OIDC callback. The authorization start action is `soca_start`. Upgrading from OAuth CIMD Auth changes the published callback and self-hosted client identifier; proxy identifiers also change because the callback is encoded in their metadata. Start a fresh login after upgrading. Provider consent may be requested again, and a pairwise subject may change. SOCA will not silently replace an existing issuer/subject binding; if that occurs, a local administrator can use the explicit WP-CLI unlink command below before a fresh verified-email login.

RESOAuth currently advertises CIMD through a vendor field, but not through the draft's standard field. Review [the recorded evidence](docs/STANDARDS.md). The plugin rejects an explicit standard `false`; an absent flag remains unconfirmed until an actual login succeeds. No RESOAuth-specific field affects plugin behavior. Changing provider only requires settings changes.

Provider acceptance of redirect origins, query-bearing client URLs, inline JWKS and the configured key-cache window must be tested. Discovery/document checks are not proof of a successful end-user login. The live RESOAuth user-login flow is **unverified**; realistic mock profiles and actual WordPress flows were tested. No certification is claimed.

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

## Account linking and recovery

- Identity is keyed by exact **issuer + subject**, with a unique per-user/per-issuer binding in a per-site table. Email is admission information, not the persistent identity key. Email/role changes are never copied to an existing account during login.
- A verified email from the configured provider can match any existing site member on first login, including an administrator. This gives that provider a route to the account's existing WordPress role, so choose a provider whose email verification you trust for every admitted domain. The plugin never assigns roles from provider claims.
- Signing in with a verified email that matches an eligible local user links the identity automatically. No profile controls or separate linking step are needed.
- A changed pairwise subject will **not** silently replace an existing identity via email matching. If you have confirmed the provider changed the subject after a client ID change, recover locally and run `wp soca unlink USER_ID` for the affected account on the correct site, then start a fresh upstream login. This removes only that user’s binding for the configured issuer. A different verified email for an already-linked subject does not change the local email or identity.
- `?soca_local=1` only skips automatic navigation. It does not authenticate anyone. Existing `?oauth_cimd_local=1` bookmarks still work. Password recovery, reset, interim login and logout flows are preserved. Local logout ends the WordPress session only; it does not claim provider-wide logout.

Emergency recovery in `wp-config.php`:

```php
define('SOCA_DISABLED', true);
```

Or run `wp soca disable`. Deactivating the plugin also leaves standard WordPress login available. Keys and identity bindings are retained on deactivation and uninstall by default. To deliberately erase plugin data during uninstall, first set `SOCA_ERASE_DATA` to `true`; this is destructive, affects every site on a multisite install, and does not delete WordPress users. Back up beforehand and remove that constant afterward. The legacy `OAUTH_CIMD_AUTH_DISABLED` and `OAUTH_CIMD_AUTH_ERASE_DATA` constants remain supported.

## Rotation, proxy behavior and operations

See [rotation and security details](docs/SECURITY.md). Two P-256 keys are generated locally and stored encrypted in non-autoloaded site options. Public endpoints publish only public keys. A replacement is validated at its actual public document/JWKS URL and warmed for the configured provider cache window before use. Automatic weekly promotion retains the previous key for at least that window plus 12 minutes. Missed cron, an unavailable document/mirror, or a long cache window delays rotation. A calendar deadline never deletes a needed transaction key.

The default provider cache safety window is **24 hours**, an operator-configurable estimate, not a measured RESOAuth cache policy. Confirm the provider's maximum caching bound and increase this setting when necessary. A window approaching/exceeding half a week conflicts with weekly rollover under the two-key limit; the plugin keeps safe overlap and reports overdue rotation through Site Health.

Proxy substitution uses one literal `%s` in the HTTPS URL path. It encodes the public metadata template as unpadded UTF-8 base64url and omits `client_id`; the service must insert the exact resulting fetch URL. Other valid `%xx` encodings are preserved. Both the example `{}` response and a full public metadata round trip were checked on 16 October 2026. The example is not a complete client configuration. The plugin does not deploy a proxy.

In proxy + inline mode, staging a new public key changes the encoded document and therefore the client identifier. Consent may repeat and pairwise subjects may change. The plugin preserves in-flight client IDs/keys and never silently relinks. A **stable public JWKS URL** keeps encoded metadata stable across key rotation. If using an external mirror, export public keys with `wp soca jwks` and publish **both** keys; an unattended weekly rotation requires an automated mirror. No private key export is provided.

WP-Cron runs maintenance hourly. Use real cron on low-traffic sites:

```sh
wp --path=/srv/wordpress --url=https://site.example.org soca maintain
```

Schedule that command hourly with your host's scheduler. Do not run it as a substitute for provider cache confirmation. Additional commands:

```sh
wp soca status   # redacted state, key IDs, publication/rotation times
wp soca check    # live discovery, actual metadata and public-key check
wp soca maintain # expiry cleanup, publication verification, safe rotation
wp soca jwks     # public keys only, for a stable mirror
wp soca audit    # last 100 redacted event codes and local user IDs
wp soca disable # disable upstream button/automatic mode
wp soca unlink USER_ID # deliberately clear this site's configured-provider binding
```

The earlier `wp oauth-cimd` command remains an alias for existing jobs; use `wp soca` in new scripts.

On multisite, always select the site with `--url`. Settings, policy, encrypted keys, transactions and identity bindings are isolated per site. New sites initialize lazily on first request. Site Health reports missing/stale maintenance and overdue rotation; its debug export excludes secrets. Web-server/proxy logs should omit callback query strings because authorization responses contain short-lived codes and state. The plugin's own audit never records these, emails, subjects, passwords, raw provider errors or tokens.

Theme integration:

```php
if (function_exists('soca_button')) {
    echo soca_button(home_url('/members/'));
}
```

The helper returns escaped markup with class `soca-login`. Only same-origin local destinations are accepted.

## Development and validation

The plugin, repository tooling and documentation are AGPL-3.0-only (see the root and bundled plugin LICENSE files). The bundled php-jwt library retains its BSD-3-Clause license.

The implementation is plain PHP/WordPress with one runtime library: `firebase/php-jwt` **7.2.1**, pinned by commit, lockfile and archive digest, with only its namespace changed to avoid conflicts with other plugins. Review and update it deliberately using `python3 tools/vendor.py`; see `simple-oauth-cimd-access/vendor/VERSION.json`. `composer audit --locked` checks the dependency inventory; root Composer output is not the production loader.

```sh
php tests/protocol.php
# Or with a container:
docker run --rm -v "$PWD:/app:ro" -w /app php:8.3-cli php tests/protocol.php
python3 tools/build.py
```

[TESTING.md](docs/TESTING.md) documents the real WordPress, concurrent-request, browser and multisite suites, exact tested profiles and limitations. Test fixtures live outside the installable plugin and must never be deployed to production. `tools/build.py` excludes all test fixtures, runtime databases, credentials and scratch work from release archives.
