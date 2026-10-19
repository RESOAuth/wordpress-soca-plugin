=== Simple OAuth CIMD Access ===
Tags: single sign on, openid connect, oauth, login, authentication
Requires at least: 6.8
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.2.0
License: AGPL-3.0-only
License URI: https://www.gnu.org/licenses/agpl-3.0.html

Add WordPress single sign-on with OpenID Connect, PKCE and Client ID Metadata Documents. Built by RESOAuth.

== Description ==

SOCA connects a WordPress site to one configured OpenID Connect (OIDC) identity provider. It starts with RESOAuth settings and can use another provider that supports the required OIDC, PKCE, private_key_jwt and Client ID Metadata Document (CIMD) features. Its client identity is a published HTTPS metadata URL with locally generated signing keys, so it does not require a shared client secret or manual registration with a compatible provider. It does not make WordPress an OAuth server.

Features:

* Self-hosted or configurable HTTPS proxy client metadata, with public JWKS and encrypted, rotating signing keys.
* Verified-email and exact-domain admission rules, including deny rules. Existing accounts are selected by the current verified email on every login; roles are not changed.
* Optional creation of missing Subscriber accounts, off by default.
* Login button, provider test flow, local-login recovery, redacted audit events, Site Health checks and WP-CLI maintenance.

An identity provider that verifies an allowed administrator email can sign in to that administrator account. Review the provider and admission rules before enabling login. Keep a local administrator password and test recovery. A successful metadata check does not prove end-to-end login: a real login with the chosen provider is required. Live RESOAuth end-user login has not yet been verified; no interoperability certification is claimed.

The [source repository](https://github.com/RESOAuth/wordpress-soca-plugin) contains the [operator guide](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/docs/GUIDE.md), [security notes](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/docs/SECURITY.md), build tools and readable source for the bundled JWT library. Report problems in [GitHub Issues](https://github.com/RESOAuth/wordpress-soca-plugin/issues).

= External services and privacy =

The initial issuer, [auth.resoauth.cloud](https://auth.resoauth.cloud), is the [RESOAuth Ltd hosted Smart Access Gateway](https://sag.resoauth.dev/hosted). Its [hosted provider docs](https://sag.resoauth.dev/hosted/connect) explain how applications connect and how visitors sign in through an existing identity provider or an emailed one-time code. Review the hosted gateway's [privacy notice](https://sag.resoauth.dev/hosted/privacy-notice) and [terms of service](https://sag.resoauth.dev/hosted/terms-of-service) before enabling it. SOCA can instead use another compatible provider configured in Settings > SOCA; that provider's own policies apply.

During connection checks, login and hourly maintenance while upstream login is enabled, SOCA fetches the selected provider's discovery document and public keys. Login redirects the visitor's browser to that provider and exchanges an authorization code at its token endpoint. The client identifier points the provider to this site's public metadata, including its callback URL and public signing keys. The provider processes the visitor's login and returns identity claims, including verified email, to this WordPress site. It sees the visitor's IP address and browser details during login. Maintenance does not contact external services while upstream login is disabled.

For local development, proxy mode defaults to [RESOAuth Dynamic CIMD](https://dynamic-cimd.resoauth.cloud/), a separate service that serves a Client ID Metadata Document from data encoded in its URL. That URL contains this site's public client metadata and, when inline keys are selected, public signing keys. The service receives the requesting server's IP address during validation, login and enabled-site maintenance; its public URL can also be fetched by the configured identity provider. SOCA sends it no WordPress passwords, private signing keys or returned identity claims. Public production sites default to self-hosted metadata; the proxy template is configurable. The [operator guide](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/docs/GUIDE.md) explains proxy choices.

SOCA stores encrypted private signing keys and settings on the WordPress site. During login it temporarily stores a one-time transaction and processes the verified email and provider subject to select an account. Its redacted audit omits emails, subjects and tokens. It does not add third-party tracking assets or send usage telemetry. Site owners should describe their chosen identity provider in their own privacy policy.

== Installation ==

1. Install and activate SOCA on WordPress 6.8+ with PHP 8.1+, OpenSSL and cURL. Use HTTPS and retain a local administrator login.
2. Open Settings > SOCA. Check the issuer, metadata mode, signing-key publication and email/domain admission rules. Defaults use RESOAuth; public HTTPS sites initially suggest the site's own domain.
3. Run Validate connection and documents, then Test login with the chosen provider. Confirm a real sign-in and local recovery at /wp-login.php?soca_local=1 before enabling automatic redirection.
4. For provider-specific settings, key rotation or multisite, follow the [operator guide](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/docs/GUIDE.md).

== Frequently Asked Questions ==

= Can I use a provider other than RESOAuth? =
Yes, if it supports this plugin's OIDC, PKCE, ES256 private_key_jwt and CIMD profile. Choose the issuer and other settings in Settings > SOCA, then validate documents and complete a real test login. Provider acceptance of query-bearing client URLs and the configured key-cache window must be checked.

= How do I recover local administrator access? =
Open /wp-login.php?soca_local=1 to skip automatic navigation, then use your existing WordPress credentials. For emergency recovery, set SOCA_DISABLED to true in wp-config.php or run wp soca disable. The URL alone does not authenticate anyone.

= How are existing accounts selected? =
The current verified provider email must pass the saved admission rules and uniquely match a WordPress account. This includes administrators, so use a provider whose email verification you trust. A changed provider subject does not relink the account, and SOCA does not change its role.

= Is data removed on uninstall? =
Settings and encrypted keys are retained by default for recovery. Define SOCA_ERASE_DATA as true before uninstall to remove persistent settings, signing keys and audit data. Short-lived transients expire through WordPress. WordPress users are never deleted by uninstall.

== Changelog ==

= 0.2.0 =
Standardize SOCA naming and replace the custom transaction table with encrypted WordPress transients. Use WordPress user APIs for account lookup and safe redirects for authorization.

= 0.1.1 =
Prepare the directory submission against the current WordPress guidelines: ship a lean installable ZIP, use prepared table identifiers, and tighten callback input handling.

= 0.1.0 =
Prepare the 0.1.0 WordPress.org release: align RESOAuth metadata, document external services, use the WordPress HTTP API with DNS-pinned HTTPS requests, and package user documentation. Login policy and OIDC validation remain as in 0.0.5.

Earlier changes are in the [release history](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/docs/CHANGELOG.md).
