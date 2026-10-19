# WordPress.org submission check

Plugin Check 2.1.0 was run against the built 0.2.0 plugin ZIP in a disposable WordPress 7.1.3/PHP 8.3 installation on 19 October 2026. It reported **zero errors and 15 warnings**: 14 public-flow nonce recommendations and one prefix warning for the WordPress core `wp_login` action. The earlier submitted package reported 58 warnings.

| Finding | Count | Review |
| --- | ---: | --- |
| `WordPress.Security.NonceVerification.Recommended` | 14 | Public metadata and JWKS are read-only routes. An ordinary login start cannot require a WordPress form nonce before authentication. The callback validates one-time state, PKCE, issuer, nonce and a signed ID token. Administrator test login requires `manage_options` and a nonce; settings POST requires both. |
| `WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound` | 1 | `wp_login` is a WordPress core action that integrations expect after a successful login. |

The plugin uses the `SOCA` PHP namespace, `soca_*` hooks and storage names, and the display name **Simple OAuth CIMD Access**. It has no custom database tables. Encrypted login transactions use ten-minute WordPress transients. Database advisory locks serialize their consumption and account creation; WordPress user APIs perform account lookup. The only direct database calls left are advisory-lock acquisition and release. The built ZIP includes `composer.json` alongside its isolated JWT dependency.

A live end-user login through the selected identity provider remains a separate verification step.
