# Deployment configuration

SOCA 0.3.0 uses one validation path for deployment values, WP-CLI and the existing
WordPress settings screen. No settings form must be saved to apply deployment
configuration. Effective precedence is **defaults < saved site settings <
SOCA_CONFIG**. A key present in SOCA_CONFIG is locked in the GUI; crafted form
posts and CLI writes cannot replace it. Removing an override reveals the previous
saved value or the default. Multisite applies the constant on each site; use
conditional deployment code when sites need different values.

Provision keys/salts through the host's secret-management process. Before loading
WordPress, set SOCA_ENCRYPTION_KEY to a stable secret of at least 32 random bytes
when using a separate encryption root. Otherwise the plugin derives its root from
the WordPress authentication keys/salts. Do not put private keys or secrets in
SOCA_CONFIG or the database configuration JSON.

```php
// wp-config.php, before WordPress loads.
define('SOCA_CONFIG', [
    'issuer' => 'https://auth.resoauth.cloud',
    'enabled' => true,
    'automatic' => false,
    'mode' => 'self',
    'key_mode' => 'uri',
    'allow_domains' => ['example.com', '*.example.com'],
    'deny_domains' => ['blocked.example.com', '*.blocked.example.com'],
    'create_users' => false,
    'tos_uri' => 'https://www.example.com/terms/',
]);
```

`enabled=true` requests activation; ordinary SSO remains unavailable until an
admitted operator test login succeeds for the effective candidate. Candidate
metadata is published while ordinary login is disabled. A real test validates
provider signatures, fresh authentication and admission without creating/linking
accounts, writing profiles/roles or replacing the operator's session.

Use the CLI for setup and maintenance:

```sh
wp plugin activate simple-oauth-cimd-access
wp soca config
wp soca configure /secure/deployment/soca.json
wp soca check
wp soca test-url --user=localadmin
wp soca status
wp soca link --user=localadmin 42 'https://auth.resoauth.cloud' 'exact-provider-subject'
wp soca unlink --user=localadmin 42 'https://auth.resoauth.cloud' 'exact-provider-subject'
wp soca maintain
wp soca disable
```

Identity approval and revocation require `--user=<administrator>`; audit entries record the local actor and target IDs.

`configure` accepts a JSON object containing any supported setting, with booleans,
integers, strings and string-array rule lists. Unknown names are rejected. Changes
to unlocked settings merge with previous values, so repeat deployments preserve
omitted fields. An unchanged configuration is a no-op and preserves in-flight revisions. `config` shows effective values and deployment locks, including
admission lists; restrict its output to operators. This is separate from the
redacted health/status export. The supported names are listed below.

Open the one-use `test-url` in a browser authenticated locally as the selected
administrator. It expires after ten minutes and requires that same operator and
configuration revision. Ordinary WordPress login suffices; no settings page or
form save is needed. Interactive authentication at the provider remains necessary.
The test result and activation status are available with `wp soca status`.
Enabling automatic redirects or the button preserves an otherwise unchanged
candidate test; changing issuer, callback, admission rules, metadata or inline keys
requires a fresh test. Any settings save invalidates existing in-flight flows.

| Setting | Default and validation |
| --- | --- |
| enabled, automatic, create_users, unrestricted | false. JSON/PHP booleans preferred; 0/1 accepted. Unrestricted bypasses allowlists, never denylists. Provisioning is fixed to Subscriber. |
| provider, button | RESOAuth; Continue with SSO. Plain text, 1–120 bytes. |
| issuer | https://auth.resoauth.cloud. Exact public HTTPS issuer, no query/userinfo/fragment. |
| scopes | openid email profile. Space-separated OAuth scope syntax, <=500 bytes; openid and email required. Request only necessary scopes. |
| mode, key_mode | Public host: self/uri; local host: proxy/inline. Allowed values self or proxy; uri or inline. |
| proxy | https://dynamic-cimd.resoauth.cloud/cimd/%s. Exactly one literal %s in an HTTPS path. Set this value to reset to the default. |
| jwks_url | Empty, deriving the site's public JWKS endpoint. Override must be public HTTPS. |
| id_alg | ES256. Explicit RS256 alternative for ID tokens; assertions remain ES256. |
| assertion_audience | issuer. Alternative token_endpoint uses its exact discovered URL. |
| cache_hours | 24; integer 1–168 hours. Confirm the provider's actual maximum cache lifetime. |
| allow_domains, deny_domains | Suggested exact site hostname in allow_domains; empty deny list. Arrays or separated text, <=200 entries and <=32000 bytes per list. Exact domains or one leading *. followed by a dotted domain. |
| allow_emails, deny_emails | Empty. Arrays or separated text, <=200 ASCII emails per list; verified email required. |
| client_name | Empty override uses the WordPress site name. Plain text <=120 bytes. |
| client_uri | Empty override uses the WordPress home URL. Explicit overrides require public HTTPS. |
| logo_uri | Empty override uses the WordPress Site Icon URL when public HTTPS; otherwise omitted. |
| policy_uri | Empty override uses WordPress's published privacy-policy URL when public HTTPS; otherwise omitted. |
| tos_uri | Empty by default, omitted. WordPress has no core terms-page API; set a published public HTTPS terms URL explicitly. |

Metadata uses application identity, not the identity provider's branding or legal
pages. Optional unavailable/unsafe platform URLs are omitted. Explicit overrides
must pass validation. Hosted and proxy metadata share the same generation path.

Emergency disable is independent of deployment locks:

```php
define('SOCA_DISABLED', true);
```

Roll it out to every PHP worker and run `wp soca status` with the flag present.
The first observation changes the persisted security epoch, invalidating pending
ordinary/test flows and activation evidence even after the flag is removed. PHP
opcode-cache/deployment propagation is the host's responsibility. `wp soca disable`
clears unlocked enablement and invalidates the same evidence; if enabled is locked
true, the emergency constant provides durable disablement. Existing WordPress
sessions survive disable/deactivation; unlinking an identity ends all sessions for
its local account. Retest after recovery.

Forms include a revision check and reject stale writes. Keep configuration JSON
and deployment revisions in your normal version-controlled deployment process for
rollback, excluding secrets. No automatic settings history or database rollback
engine is provided. Restoring old database backups can restore old links/evidence;
reconcile revocations and run emergency disable before restoring service.
