=== SOCA - Simple OAuth CIMD Access ===
Contributors: olliejc
Tags: openid-connect, oauth, login, cimd, pkce
Requires at least: 6.8
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.0.5
License: AGPLv3
License URI: https://www.gnu.org/licenses/agpl-3.0.html

SOCA (Simple OAuth CIMD Access) is open-source WordPress single sign-on built and supported by RESOAuth®.

== Description ==
SOCA is an open-source RESOAuth® plugin that also supports other compatible configured providers. OAuth redirects the browser securely; OpenID Connect establishes the user's identity; CIMD publishes this site's client details and public keys.

One configurable OIDC provider per site. Initial settings use RESOAuth. Self-hosted and configurable HTTPS proxy CIMD modes, public JWKS, encrypted P-256 client keys, safe weekly rotation, verified-email account selection on every login, admission policies and optional controlled Subscriber registration.

See the bundled README.md, SECURITY.md and STANDARDS.md for setup, protocol choices, live evidence, local Docker development, rotation and recovery. No certification is claimed. Full live RESOAuth login is unverified; realistic mock and WordPress integration/browser profiles are tested.

== Installation ==
1. Upload and activate the ZIP. PHP OpenSSL and cURL are required.
2. Open Settings > SOCA. Review issuer, metadata, admission rules and local recovery.
3. Public HTTPS sites enable the upstream button with a suggested domain allowlist on first activation. Validate connection/documents and test login. Local development sites need an admission rule and manual enablement.

== Frequently Asked Questions ==
= How do I recover local administrator access? =
Use /wp-login.php?soca_local=1. This skips automatic navigation only. You must still authenticate. Set SOCA_DISABLED=true in wp-config.php or run wp soca disable for emergency recovery.

= Does proxy mode expose private keys? =
No. Only public metadata and public keys are encoded. Proxy + inline key rotation changes client_id and can change pairwise subjects. Use a stable public JWKS URL for stable client identity.

= Are existing accounts matched by email automatically? =
Yes. A verified email from the configured provider selects the matching local account on every login, including an administrator. The local role is never changed. Choose a provider that reliably verifies addresses in your admission policy. A changed provider subject does not require relinking.

= Are keys and old binding rows deleted on uninstall? =
No, unless SOCA_ERASE_DATA is explicitly set to true before uninstall. Old binding rows are no longer used for login. WordPress users are never deleted by uninstall.

== Changelog ==
= 0.0.5 =
Use a direct OIDC callback without a SOCA transaction cookie. Preserve one-time state, PKCE, nonce, token validation, verified-email account selection and redacted audit events. See SECURITY.md for the login CSRF limitation of an unbound callback.

= 0.0.4 =
Distinguish missing and mismatched browser cookies in redacted audit events, keep the login reference across transaction failures, and report whether the start and callback hostnames match.

= 0.0.3 =
Select accounts by the current verified email on every login, remove subject binding from the login path, and add redacted step/reason/reference audit diagnostics.

= 0.0.2 =
Use SOCA names consistently across recovery, diagnostics and maintenance, retain legacy compatibility, and default the login button to "Continue with SSO".

= 0.0.1 =
Initial SOCA release: OIDC code flow with PKCE, CIMD metadata, verified-email access policy, identity binding, public key rotation, diagnostics and local recovery.
