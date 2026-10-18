# Security and protocol decisions

This document describes the implemented profile, not a formal certification or security audit. Baseline references and live evidence are in [STANDARDS.md](STANDARDS.md).

## Protocol requirements versus product choices

| Area | Protocol basis | This plugin's profile |
| --- | --- | --- |
| User identity | OIDC Core defines authentication; OAuth alone does not | Require OIDC, exact configured issuer, subject types, code response, verified email in ID token or subject-matched UserInfo. No OAuth-only identity inference. |
| PKCE and request correlation | OAuth 2.1 draft 16, RFC 9700 and RFC 7636 | Always S256, including confidential requests; also independent 256-bit state and nonce. Require advertised S256. |
| Transactions | CSRF, replay and mix-up protection | Ten-minute encrypted server-side record, independent `__Host-` Secure/HttpOnly/SameSite=Lax browser cookie (no Domain attribute, path `/`), atomic delete-on-consume. Snapshot issuer, endpoints, client ID, callback, nonce, verifier, key ID and settings. A settings save invalidates pending transactions. A missing or mismatched browser cookie is rejected and recorded under the start attempt's audit reference. |
| Client authentication | RFC 7523 and OIDC private_key_jwt | ES256/P-256 only, `iss=sub=client_id`, audience the configured provider issuer or its exact discovered token endpoint, random `jti`, 60-second expiry. The audience is snapshotted with the transaction. Require advertised private_key_jwt and ES256. No client secrets or downgrade. |
| Token signatures | OIDC Core, RFC 8725, RFC 7517 | Administrator pins ES256 or RS256 for ID tokens. Require `kid`; reject duplicate matching keys, `none`, HMAC, remote/embedded header keys, critical JOSE extensions and non-JWT `typ`. Use only the pinned issuer's discovered JWKS; never client signing keys. |
| ID token claims | OIDC Core §3.1.3.7 | Exact issuer, nonempty ASCII subject ≤255 bytes, audience membership, `azp` required with multiple audiences and checked whenever present, exact nonce, signature, expiry, future `iat`/`nbf`, and hashes when present. 60-second clock tolerance, integer times, `iat` no earlier than transaction start minus tolerance, lifetime ≤24 hours. These last age/type bounds are stricter choices. |
| Reauthentication | OIDC max_age, auth_time, prompt | Administrator test login uses max_age=0/prompt=login; require auth_time within the transaction window. Validate optional auth_time, acr and amr types; arbitrary acr/amr/role/tenant claims never grant privileges. The plugin does not claim an MFA assurance level. |
| Authorization response issuer | RFC 9207 | Validate `iss` whenever present and require it when advertised. Otherwise the single pinned issuer, snapshotted endpoints and configuration revision provide the one-provider mix-up boundary. No issuer from browser/email/claims. |
| Transport | OIDC Discovery, RFC 9700, CIMD draft | HTTPS for every outbound endpoint and web callback, including development. Some OAuth profiles permit loopback HTTP; this web client deliberately does not. No redirects on any server fetch, not merely CIMD. JSON content type, 200 status, max 256 KiB body/32 KiB headers, 5-second connection and 12-second overall timeout. |
| SSRF | CIMD security considerations and OAuth security | Public ASCII DNS names only, no IP URL/userinfo/fragment/control characters/dot segments; reject all nonpublic resolved addresses, pin the chosen address with cURL `CURLOPT_RESOLVE`, verify TLS hostname/certificate, and disable outbound proxy inheritance. DNS results cannot change the connected target between validation and connection. Network egress policy remains a useful outer boundary. |
| Caching | HTTP caching, OIDC rotation | Discovery/JWKS cache ≤1 hour and honor shorter max-age/Age/no-store/no-cache. No stale-on-error keys. Unknown `kid` or a failed signature permits one JWKS refresh; a per-provider 60-second gate bounds refresh storms. No fallback algorithm. |
| CIMD URL | CIMD draft 02 | HTTPS, exact `client_id` equality, no userinfo/fragment/dot components, exactly one proxy placeholder in the path. Self-hosted URLs use a query parameter so they work with plain WordPress permalinks: the draft's no-query recommendation is SHOULD, not MUST. A provider that disallows this must report incompatibility; the plugin does not rewrite identity silently. |
| Logout | RP-Initiated Logout 1.0 considered | Local WordPress logout only. No ID token is retained for logout hints; no provider/global/frontchannel/backchannel logout claim. |

## Key lifecycle

At first activation, generate an active key A and a replacement B. Store encrypted private material with AES-256-GCM and per-site HKDF derivation. By default the root secret comes from the WordPress authentication keys/salts in `wp-config.php`; unconfigured placeholders are refused. To separate it from WordPress cookie salts, define `OAUTH_CIMD_AUTH_KEY` as a stable, randomly generated secret of at least 32 bytes **before activation**. For example, provision a 64-character cryptographically random hex secret through your host's secret-management process. Do not commit it to this repository. Database backups and configuration backups together contain enough material to recover the keys and must be protected.

There is no key export endpoint, upload-file private key, or autoloaded plaintext private key. The plugin cannot protect secrets against arbitrary PHP execution, a malicious administrator with code installation capability, or a fully compromised host. Encryption separates a database-only disclosure from the signing root when the root stays in configuration.

The publication check fetches the exact generated metadata URL, requires all generated metadata fields to match, and checks both public keys at `jwks_uri` (or inline). Only the observed snapshot is marked published. A new active key needs publication validation before login. The replacement must have been observed for the full configured cache window before it is used.

With the default 24-hour window:

1. Day 0: publish A+B; use A after successful document validation. Record B's publication time.
2. Day 7 or later: after successful publication validation and B's warm-up, switch to B. Keep A+B published. Retire A no sooner than the cache window plus 720 seconds after the **actual** promotion, covering ten-minute transactions, one-minute assertions and clock tolerance.
3. Once that retention interval ends, replace retired A with candidate C. Still at most two stored/published keys: B+C. C begins a new publication warm-up after an actual successful fetch.
4. Day 14 or later: use C only when the current active age and C's publication window both permit it.

Cron delays, an unavailable proxy/mirror, slow caching or an operator changing publication settings extend this timeline. The rotation transition never catches up by immediately discarding keys. A retirement deadline is captured at promotion; subsequently reducing the configured cache window cannot shorten it. Increasing the window can extend retention. An external mirror that never publishes the candidate blocks its promotion. The configured cache window must cover the provider's actual bound, which discovery does not generally reveal.

Discovery that explicitly reports `client_id_metadata_document_supported: false` is refused. An absent field is treated as unconfirmed support: the document check validates the generated metadata but a real test login is needed to establish provider acceptance. No vendor-specific discovery field is interpreted.

In proxy-inline mode, **staging/removing** a key changes the encoded client document and thus its URL. Switching the active signing key alone does not change the sorted two-key document. Pending transactions retain the old client ID and signing key and can finish within their ten-minute lifetime while their callback route remains available. Old immutable proxy URLs contain only public material. A changed pairwise subject may cause fresh provider consent, but account selection continues by the current verified email. Migrating from OAuth CIMD Auth changes callback/document URLs and client identifiers; start a new login after upgrading. The legacy internal encryption context remains unchanged so existing encrypted keys stay readable.

Do not change salts or `OAUTH_CIMD_AUTH_KEY` without planning migration. Lost roots fail closed; restoring the original root restores encrypted keys. A new key set must go through fresh publication/cache checks and may affect upstream consent. Do not delete keys to force a weekly deadline.

## Accounts, concurrency and multisite

Account matching and creation use a database advisory lock shared across plugin sites in the same WordPress network. Duplicate local emails cause refusal. Concurrent plugin registrations converge on one account. Other extensions that create users independently do not share this lock; keep account provisioning controlled and resolve ambiguous emails explicitly. The plugin no longer creates or reads an issuer/subject binding table; existing rows from older releases remain untouched for backup compatibility.

Account creation uses a random local password and the Subscriber role. A failed WordPress insertion refuses login. No session is issued without selecting an eligible site member or creating a valid new account.

Every login requires a valid, verified email from the pinned provider and applies the current deny and allow rules. The email selects the matching local account, including an administrator, on every login; existing local emails, roles and capabilities are not changed. A compromised or weakly verified upstream address can grant the matched WordPress role. The subject remains mandatory and validated for OIDC, including UserInfo consistency, but it is not used as a local account key. Account creation is a separate opt-in. Rate limits are per ten-minute HMAC of the server-observed IP (30 login starts); they do not trust arbitrary forwarded IP headers. Shared reverse proxies may share a limit. Apply your normal WordPress login/edge rate controls as well.

Each site's options, encryption context, metadata URLs, transaction table/cookie prefix and admission rules are independent. Network-wide users are never silently added to another site. Removing a user from one site prevents matching that account on that site. Deactivation and uninstall retain plugin data by default.

## Data and extension boundaries

Access and refresh tokens are never saved to establish a WordPress session. A Bearer access token, if needed for UserInfo, exists only during that request and is sent only to the discovered HTTPS endpoint; UserInfo subject must exactly match the verified ID token. The last 100 audit entries contain timestamps, fixed event/step/reason codes, a random 12-character login reference, optional HTTP status or cURL error number, optional exception class for unexpected failures, and local user IDs after account selection. No claims, addresses, tokens, raw provider errors or telemetry are stored.

All settings writes require `manage_options` and a WordPress nonce. Output is escaped. Public metadata contains no policy lists, user data, private material or tokens. The `soca_http` filter allows trusted PHP integration/test code to supply an `OCIMD\Http` implementation; the earlier `oauth_cimd_auth_http` filter remains supported. Neither is an administrator UI or untrusted request setting. Test fixtures use this boundary and are excluded from releases.
