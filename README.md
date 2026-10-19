# Simple OAuth CIMD Access

SOCA adds single sign-on to WordPress through an OpenID Connect provider that supports OAuth Client ID Metadata Documents (CIMD). It is developed by [RESOAuth](https://github.com/RESOAuth), starts with RESOAuth settings, and can be configured for another compatible provider. The plugin uses authorization code with PKCE and a signed client assertion. WordPress remains the application that receives the login; SOCA does not turn it into an authorization server.

## What it does

- Publishes this site's client metadata and public signing keys through self-hosted URLs or a configurable HTTPS metadata proxy.
- Signs client assertions with encrypted, rotating P-256 keys and validates the provider's signed ID token.
- Applies email and domain admission rules to a **verified** provider email, then selects the matching local WordPress account. Optional creation is limited to Subscriber accounts.
- Provides a login button, a test-login flow, redacted diagnostics, WP-CLI maintenance commands, and a local-login recovery route.

**Security decision:** A provider that can verify an admitted administrator email can sign in as that administrator. Keep a local administrator login, review the admission rules, and test the provider before enabling automatic redirects. The browser's User-Agent is checked at callback, but it is not proof of the same browser.

## Install and configure

Download the `simple-oauth-cimd-access-0.2.0.zip` release asset when published or build it with `python3 tools/build.py`. In WordPress, choose **Plugins → Add Plugin → Upload Plugin**, activate SOCA, then open **Settings → SOCA**. It requires WordPress 6.8+, PHP 8.1+, OpenSSL, cURL, and a public HTTPS site for self-hosted metadata. The installable ZIP contains its runtime dependency; Composer is not needed on the server.

1. Keep a working local administrator password and bookmark `/wp-login.php?soca_local=1`.
2. Review the configured issuer, provider name, client metadata mode, and exact admission rules. Defaults use `https://auth.resoauth.cloud`.
3. Run **Validate connection and documents**, then **Test login**. A document check alone does not establish successful provider login.
4. Enable automatic redirection only after a successful real login and recovery check.

The initial identity provider is the [RESOAuth hosted Smart Access Gateway](https://sag.resoauth.dev/hosted), operated by RESOAuth Ltd at `https://auth.resoauth.cloud`. Its [connection guide](https://sag.resoauth.dev/hosted/connect), [privacy notice](https://sag.resoauth.dev/hosted/privacy-notice), and [terms of service](https://sag.resoauth.dev/hosted/terms-of-service) describe the hosted service. Local development defaults to [RESOAuth Dynamic CIMD](https://dynamic-cimd.resoauth.cloud/) for public client metadata. The live RESOAuth end-user login remains unverified in the recorded test results. Synthetic provider, WordPress integration, and browser flows have been tested; no certification is claimed. See the [operator guide](docs/GUIDE.md) for setup, recovery, rotation, proxy behavior, and WP-CLI commands.

## Documentation and support

- [Operator guide](docs/GUIDE.md)
- [Local development and build](docs/DEVELOPMENT.md)
- [Security and protocol decisions](docs/SECURITY.md)
- [Interoperability evidence and standards](docs/STANDARDS.md)
- [Test procedures and results](docs/TESTING.md)
- [WordPress.org Plugin Check review](docs/PLUGIN-CHECK.md)
- [Release history](docs/CHANGELOG.md)
- [Directory release notes](docs/RELEASE.md)
- [Issues and support](https://github.com/RESOAuth/wordpress-soca-plugin/issues)

The [WordPress.org listing readme](https://github.com/RESOAuth/wordpress-soca-plugin/blob/main/simple-oauth-cimd-access/readme.txt) describes the default external services and data flow. Site operators are responsible for the configured identity provider's terms and privacy information. The source, tooling, and plugin are licensed under [AGPL-3.0-only](LICENSE); the bundled `firebase/php-jwt` library retains its BSD-3-Clause license.
