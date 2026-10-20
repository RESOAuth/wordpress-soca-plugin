# SOCA user and operator guide

SOCA (Simple OAuth CIMD Access) is an open-source WordPress single sign-on plugin built and supported by RESOAuth® that can use another compatible configured provider. It uses OIDC authorization code + PKCE S256, `private_key_jwt` ES256, and self-hosted or proxy Client ID Metadata Documents (CIMD). It does **not** make WordPress an authorization server.

Install the `simple-oauth-cimd-access-0.3.0.zip` release asset using **Plugins → Add Plugin → Upload Plugin**, activate it, then open **Settings → SOCA**. PHP 8.1+, OpenSSL, cURL, and WordPress 6.8+ are required. The release contains its isolated JWT dependency; Composer is not needed on the WordPress server.

## Setup

1. Keep a local administrator account and password. Bookmark `/wp-login.php?soca_local=1`. Confirm WordPress uses HTTPS and has unique authentication keys/salts in `wp-config.php`.
2. Review the issuer, provider name and button label. Initial settings use the [RESOAuth Ltd hosted Smart Access Gateway](https://sag.resoauth.dev/hosted) at `https://auth.resoauth.cloud`, scopes `openid email profile`, ES256 client authentication. Its [connection guide](https://sag.resoauth.dev/hosted/connect) explains the hosted issuer, CIMD and sign-in methods. Read its [privacy notice](https://sag.resoauth.dev/hosted/privacy-notice) and [terms of service](https://sag.resoauth.dev/hosted/terms-of-service). Public HTTPS sites default to self-hosted CIMD and the derived JWKS URL. Local sites select the [RESOAuth Dynamic CIMD](https://dynamic-cimd.resoauth.cloud/) proxy and inline public keys. Ordinary SSO starts disabled on every site.
3. Review admission rules. The suggested domain is the exact home hostname with one leading `www.` removed; localhost, IPs and reserved development names are excluded. Deny wins; either allowlist can admit. **Allow any verified email/domain** starts off and, when selected, hides the allowlists while keeping denylists active. Exact domains match only themselves. A leading `*.` matches one or more subdomain labels and excludes the apex: `*.example.com` admits `a.b.example.com`, not `example.com` or `badexample.com`. Existing users, including administrators, require approved issuer/subject links. Registration remains off; new accounts, when enabled, are Subscribers.
4. **Validate connection and documents → Test login.** The test keeps your current administrator session, validates a fresh upstream login and reports the saved email policy without selecting or creating an account. An admitted test activates the candidate evidence; then enable the login button and optional automatic redirect. A denied test cannot activate ordinary SSO.

The separate **Test access rules** form explains how the saved allowed/denied email and domain rules treat an address. It links back to Access rules, keeps the tested address visible, and shows the result beside the field and button. Unsaved edits are not included.

The advanced **Client assertion audience** setting defaults to the provider issuer for new installations. RESOAuth's token endpoint requires that value. Other providers may require the token endpoint URL; select it in advanced settings if their profile calls for it. The selection is pinned in each login transaction and does not alter PKCE, signature checks or transport security.

Public routes use `?soca_doc=client` for self-hosted CIMD, `?soca_doc=jwks` for public keys, and `wp-admin/admin-post.php?action=soca_callback` for the OIDC callback. The authorization start action is `soca_start`.

RESOAuth currently advertises CIMD through a vendor field, but not through the draft's standard field. Review [the recorded evidence](STANDARDS.md). The plugin rejects an explicit standard `false`; an absent flag remains unconfirmed until an actual login succeeds. No RESOAuth-specific field affects plugin behavior. Changing provider only requires settings changes.

Provider acceptance of redirect origins, query-bearing client URLs, inline JWKS and the configured key-cache window must be tested. Discovery/document checks are not proof of a successful end-user login. The live RESOAuth user-login flow is **unverified**; realistic mock profiles and actual WordPress flows were tested. No certification is claimed.

For local development, see [Development and validation](DEVELOPMENT.md).

## Upgrade from 0.2.0 and headless setup

**0.3.0 intentionally ends automatic email-based account selection.** Keep local
administrator access while upgrading. Existing settings and encrypted keys are
preserved, but ordinary SSO has no current candidate-test evidence until retested.
Approve every returning user's exact issuer/subject association before rollout.
Do not import associations by matching email alone. Test a linked ordinary user,
an administrator, a changed subject and local recovery before enabling automatic
redirects. Existing WordPress sessions are preserved.

[Deployment configuration](CONFIGURATION.md) documents every supported setting,
SOCA_CONFIG precedence/locks, WP-CLI JSON setup and operator-bound test URLs.
Metadata defaults use the site's name, home URL, public Site Icon and published
privacy policy in both modes. Override application identity/legal fields under
advanced settings or in SOCA_CONFIG. WordPress has no core terms-page API, so set
tos_uri explicitly where available. [The requirement assessment](REQUIREMENTS.md)
records capabilities and outstanding gaps.

## Account selection and recovery

- On every login, the trusted provider's current verified email must pass admission. The exact issuer/subject then selects its approved local identity association. Email alone never grants access to an existing account.
- Approve an existing user's association in **Settings → SOCA → Approve or remove an identity link**, or run `wp soca link --user=localadmin <user-id> '<issuer>' '<subject>'`. Verify ownership independently and obtain the exact subject from the trusted provider. Administrator approval is the supported linking method; self-service linking is not implemented.
- A changed subject is refused until explicitly approved. A changed email never switches to another local account; existing email/profile fields, roles and capabilities remain local. Unlinked identities with an existing local email are refused, even when creation is enabled.
- Optional new-account creation is limited to Subscribers, with a random local password and identity link. Conflicts refuse login. Unlinking stores an encrypted revocation record, invalidates pending flows/activation evidence and ends all WordPress sessions for that account. It cannot automatically provision again until explicitly approved. Deleted or removed accounts are not reactivated.
- `?soca_local=1` only skips automatic navigation. It does not authenticate anyone. Password recovery, reset, interim login and logout flows are preserved. Local logout ends the WordPress session only; it does not claim provider-wide logout.

Emergency recovery in `wp-config.php`:

```php
define('SOCA_DISABLED', true);
```

Or run `wp soca disable` for unlocked settings. `SOCA_DISABLED=true` overrides even a deployment-locked enablement and blocks operator tests. Ensure every worker sees it and run `wp soca status` while it is present, so the persisted security epoch invalidates pending flows even after recovery. Deactivating the plugin also leaves standard WordPress login available. Deactivation invalidates pending flows and activation evidence. Existing WordPress sessions survive disable/deactivation. Settings, encrypted keys and encrypted identity records are retained on deactivation and uninstall by default. To remove persistent plugin settings, signing keys, identity associations and audit data during uninstall, first set `SOCA_ERASE_DATA` to `true`; this affects every site on a multisite install and does not delete WordPress users. Short-lived transients expire through WordPress. Back up beforehand and remove that constant afterward.

## Rotation, proxy behavior and operations

See [rotation and security details](SECURITY.md). Two P-256 keys are generated locally and stored encrypted in non-autoloaded site options. Public endpoints publish only public keys. A replacement is validated at its actual public document/JWKS URL and warmed for the configured provider cache window before use. Automatic weekly promotion retains the previous key for at least that window plus 12 minutes. Missed cron, an unavailable document/mirror, or a long cache window delays rotation. A calendar deadline never deletes a needed transaction key.

The default provider cache safety window is **24 hours**, an operator-configurable estimate, not a measured RESOAuth cache policy. Confirm the provider's maximum caching bound and increase this setting when necessary. A window approaching/exceeding half a week conflicts with weekly rollover under the two-key limit; the plugin keeps safe overlap and reports overdue rotation through Site Health.

Proxy substitution uses one literal `%s` in the HTTPS URL path. The default is `https://dynamic-cimd.resoauth.cloud/cimd/%s`. It serialises the public template in fixed field order with sorted public keys, unescaped Unicode/slashes and no whitespace, then uses unpadded UTF-8 base64url without `client_id`; the service must insert the exact resulting fetch URL. Other valid `%xx` encodings are preserved. The local limits are 8192 public JSON bytes and a 12288-byte resulting URL, including overlapping keys. The actual proxy/provider limits may be lower; confirm them before deployment. A public metadata round trip was checked against the new service on 19 October 2026. The plugin does not deploy a proxy. The proxy service is separate from the hosted identity provider; the gateway's terms and privacy notice linked above describe the gateway, not every possible proxy. Changing the template changes the `client_id`, so complete a fresh test login afterward.

In proxy + inline mode, staging a new public key changes the encoded document and therefore the client identifier. Consent may repeat and pairwise subjects may change. A changed metadata fingerprint requires an admitted test before further ordinary SSO. Old client IDs and keys are retained, but this does not provide uninterrupted inline-key rollover. A changed pairwise subject requires explicit link migration, never email-based recovery. A **stable public JWKS URL** keeps encoded metadata stable across key rotation. If using an external mirror, export public keys with `wp soca jwks` and publish **both** keys; an unattended weekly rotation requires an automated mirror. No private key export is provided.

WP-Cron runs maintenance hourly. With upstream login disabled, it does not contact the provider or CIMD proxy. When upstream login is enabled, it also checks public metadata and performs safe key rotation. Use real cron on low-traffic sites:

```sh
wp --path=/srv/wordpress --url=https://site.example.org soca maintain
```

Schedule that command hourly with your host's scheduler. Do not run it as a substitute for provider cache confirmation. Additional commands:

```sh
wp soca status   # redacted state, key IDs, publication/rotation times
wp soca check    # live discovery, actual metadata and public-key check
wp soca maintain # publication verification and safe rotation
wp soca jwks     # public keys only, for a stable mirror
wp soca audit    # last 100 redacted events, including login steps, reason codes and references
wp soca disable # invalidate flows/evidence and disable unlocked button/automatic mode
```

On multisite, always select the site with `--url`. Settings, policy, encrypted keys and transactions are isolated per site. New sites initialize lazily on first request. Site Health reports missing/stale maintenance and overdue rotation; its debug export excludes secrets. Web-server/proxy logs should omit callback query strings because authorization responses contain short-lived codes and state. A failed login shows a 12-character reference; find the matching `login_failed` event in **Settings → SOCA → Recent redacted audit events** or `wp soca audit`. Its `step` and `reason` show where the attempt stopped; outbound failures include an HTTP status when an endpoint responds with an error. The audit never records emails, subjects, passwords, raw provider errors or tokens.

Each transaction uses an independent 256-bit browser secret in a ten-minute, host-only Secure/HttpOnly/SameSite=Lax cookie. It contains no verifier, nonce or token. An encrypted WordPress transient holds the secret hash and confidential protocol state. The callback validates the browser binding and User-Agent before atomically consuming the state; it then deletes that cookie. Abandoned cookies expire automatically. Parallel tabs have distinct cookies. No localStorage, sessionStorage or IndexedDB is used. See [SECURITY.md](SECURITY.md).

Theme integration:

```php
if (function_exists('soca_button')) {
    echo soca_button(home_url('/members/'));
}
```

The helper returns escaped markup with class `soca-login`. Only same-origin local destinations are accepted.
