# SOCA user and operator guide

SOCA (Simple OAuth CIMD Access) is an open-source WordPress single sign-on plugin built and supported by RESOAuth® that can use another compatible configured provider. It uses OIDC authorization code + PKCE S256, `private_key_jwt` ES256, and self-hosted or proxy Client ID Metadata Documents (CIMD). It does **not** make WordPress an authorization server.

Install the `simple-oauth-cimd-access-0.1.0.zip` release asset using **Plugins → Add Plugin → Upload Plugin**, activate it, then open **Settings → SOCA**. PHP 8.1+, OpenSSL, cURL, and WordPress 6.8+ are required. The release contains its isolated JWT dependency; Composer is not needed on the WordPress server.

When upgrading from the old `oauth-cimd-auth` folder, install the new ZIP, deactivate **OAuth CIMD Auth**, then activate **SOCA**. Both folders must not run together. Existing site settings and encrypted keys are retained under their original internal database names. Old issuer/subject binding rows are left in place for backup compatibility but are no longer used for login. The internal `OCIMD` PHP namespace and `ocimd_*` storage names remain for compatibility. Check the new client metadata URL and complete a fresh test login before removing the old folder.

## Setup

1. Keep a local administrator account and password. Bookmark `/wp-login.php?soca_local=1`. Confirm WordPress uses HTTPS and has unique authentication keys/salts in `wp-config.php`.
2. Review the issuer, provider name and button label. Initial settings use the [RESOAuth Ltd hosted Smart Access Gateway](https://sag.resoauth.dev/hosted) at `https://auth.resoauth.cloud`, scopes `openid email profile`, ES256 client authentication. Its [connection guide](https://sag.resoauth.dev/hosted/connect) explains the hosted issuer, CIMD and sign-in methods. Read its [privacy notice](https://sag.resoauth.dev/hosted/privacy-notice) and [terms of service](https://sag.resoauth.dev/hosted/terms-of-service). Public HTTPS sites default to self-hosted CIMD and the derived JWKS URL, and show the login button on activation. Local sites select the [RESOAuth Dynamic CIMD](https://dynamic-cimd.resoauth.cloud/) proxy and inline public keys; their login button stays off until an admission rule is chosen.
3. Review admission rules. The suggested domain is the exact home hostname with one leading `www.` removed; localhost, IPs and reserved development names are excluded. Deny wins; either allowlist can admit. **Allow any verified email/domain** starts off and, when selected, hides the allowlists while keeping denylists active. Domains match exactly. First-login verified-email matching includes existing administrator accounts by default. Registration remains off; new accounts, when enabled, are Subscribers.
   On upgrade, a previously saved unrestricted flag is cleared when allowlists were populated, preserving the old effective policy until an administrator deliberately selects Allow any.
4. **Validate connection and documents → Test login.** The test keeps your current administrator session, validates a fresh upstream login and reports the saved email policy without selecting or creating an account. Automatic redirect is optional.

The separate **Test access rules** form explains how the saved allowed/denied email and domain rules treat an address. It links back to Access rules, keeps the tested address visible, and shows the result beside the field and button. Unsaved edits are not included.

The advanced **Client assertion audience** setting defaults to the provider issuer for new installations. RESOAuth's token endpoint requires that value. Other providers may require the token endpoint URL; select it in advanced settings if their profile calls for it. Existing installations retain their previous token endpoint audience until changed. The selection is pinned in each login transaction and does not alter PKCE, signature checks or transport security.

Public routes use `?soca_doc=client` for self-hosted CIMD, `?soca_doc=jwks` for public keys, and `wp-admin/admin-post.php?action=soca_callback` for the OIDC callback. The authorization start action is `soca_start`. Upgrading from OAuth CIMD Auth changes the published callback and self-hosted client identifier; proxy identifiers also change because the callback is encoded in their metadata. Start a fresh login after upgrading. Provider consent may be requested again, and a pairwise subject may change. Account selection uses the current verified email regardless of that subject change.

RESOAuth currently advertises CIMD through a vendor field, but not through the draft's standard field. Review [the recorded evidence](STANDARDS.md). The plugin rejects an explicit standard `false`; an absent flag remains unconfirmed until an actual login succeeds. No RESOAuth-specific field affects plugin behavior. Changing provider only requires settings changes.

Provider acceptance of redirect origins, query-bearing client URLs, inline JWKS and the configured key-cache window must be tested. Discovery/document checks are not proof of a successful end-user login. The live RESOAuth user-login flow is **unverified**; realistic mock profiles and actual WordPress flows were tested. No certification is claimed.

For local development, see [Development and validation](DEVELOPMENT.md).

## Account selection and recovery

- On every login, SOCA checks the current, valid, verified email from the configured provider against the saved admission rules, then selects the unique matching WordPress user on this site. The subject is still validated as part of OIDC and used to match UserInfo, but no subject binding is stored or consulted for account selection.
- A changed pairwise subject with the same verified email selects the same account. If the provider returns a different verified email, that address selects its matching local account. SOCA does not change existing WordPress email addresses, roles or capabilities.
- A provider that verifies an admitted administrator email can access that administrator account. Choose a provider whose email verification you trust for every admitted domain. Duplicate local email rows and nonmember accounts are refused. Missing accounts are created as Subscribers only when **Create missing accounts** is enabled.
- `?soca_local=1` only skips automatic navigation. It does not authenticate anyone. Existing `?oauth_cimd_local=1` bookmarks still work. Password recovery, reset, interim login and logout flows are preserved. Local logout ends the WordPress session only; it does not claim provider-wide logout.

Emergency recovery in `wp-config.php`:

```php
define('SOCA_DISABLED', true);
```

Or run `wp soca disable`. Deactivating the plugin also leaves standard WordPress login available. Keys and legacy binding rows are retained on deactivation and uninstall by default. To deliberately erase plugin data during uninstall, first set `SOCA_ERASE_DATA` to `true`; this is destructive, affects every site on a multisite install, and does not delete WordPress users. Back up beforehand and remove that constant afterward. The legacy `OAUTH_CIMD_AUTH_DISABLED` and `OAUTH_CIMD_AUTH_ERASE_DATA` constants remain supported.

## Rotation, proxy behavior and operations

See [rotation and security details](SECURITY.md). Two P-256 keys are generated locally and stored encrypted in non-autoloaded site options. Public endpoints publish only public keys. A replacement is validated at its actual public document/JWKS URL and warmed for the configured provider cache window before use. Automatic weekly promotion retains the previous key for at least that window plus 12 minutes. Missed cron, an unavailable document/mirror, or a long cache window delays rotation. A calendar deadline never deletes a needed transaction key.

The default provider cache safety window is **24 hours**, an operator-configurable estimate, not a measured RESOAuth cache policy. Confirm the provider's maximum caching bound and increase this setting when necessary. A window approaching/exceeding half a week conflicts with weekly rollover under the two-key limit; the plugin keeps safe overlap and reports overdue rotation through Site Health.

Proxy substitution uses one literal `%s` in the HTTPS URL path. The new default is `https://dynamic-cimd.resoauth.cloud/cimd/%s`. It encodes the public metadata template as unpadded UTF-8 base64url and omits `client_id`; the service must insert the exact resulting fetch URL. Other valid `%xx` encodings are preserved. A public metadata round trip was checked against the new service on 19 October 2026. The plugin does not deploy a proxy. The proxy service is separate from the hosted identity provider; the gateway's terms and privacy notice linked above describe the gateway, not every possible proxy. Previously saved proxy templates remain unchanged on upgrade to avoid silently changing client identifiers; inspect and update **Settings → SOCA → CIMD proxy template** if you want an existing site to use the new default. Changing the template changes the `client_id`, so complete a fresh test login afterward.

In proxy + inline mode, staging a new public key changes the encoded document and therefore the client identifier. Consent may repeat and pairwise subjects may change. The plugin preserves in-flight client IDs/keys; account selection still uses the current verified email. A **stable public JWKS URL** keeps encoded metadata stable across key rotation. If using an external mirror, export public keys with `wp soca jwks` and publish **both** keys; an unattended weekly rotation requires an automated mirror. No private key export is provided.

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
wp soca audit    # last 100 redacted events, including login steps, reason codes and references
wp soca disable # disable upstream button/automatic mode
```

The earlier `wp oauth-cimd` command remains an alias for existing jobs; use `wp soca` in new scripts.

On multisite, always select the site with `--url`. Settings, policy, encrypted keys and transactions are isolated per site. New sites initialize lazily on first request. Site Health reports missing/stale maintenance and overdue rotation; its debug export excludes secrets. Web-server/proxy logs should omit callback query strings because authorization responses contain short-lived codes and state. A failed login shows a 12-character reference; find the matching `login_failed` event in **Settings → SOCA → Recent redacted audit events** or `wp soca audit`. Its `step` and `reason` show where the attempt stopped; outbound failures include an HTTP status when an endpoint responds with an error. The audit never records emails, subjects, passwords, raw provider errors or tokens.

SOCA does not set a temporary login cookie. The callback checks the User-Agent, consumes the one-time database transaction, exchanges the code, validates the signed ID token and verified email, then issues normal WordPress authentication cookies. Audit events identify failed steps and reasons, including `user_agent_mismatch`. Matching User-Agents do not prove the same browser; see [SECURITY.md](SECURITY.md).

Theme integration:

```php
if (function_exists('soca_button')) {
    echo soca_button(home_url('/members/'));
}
```

The helper returns escaped markup with class `soca-login`. Only same-origin local destinations are accepted.
