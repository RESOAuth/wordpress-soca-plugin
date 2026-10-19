# Standards and live interoperability evidence

Checked **16 October 2026** against authoritative sources before implementation. Both of the following remain **Internet-Drafts**, not published RFCs:

- [OAuth 2.1 - draft-ietf-oauth-v2-1-16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16), published 3 September 2026; expires 7 March 2027. The unversioned IETF page resolved to revision 16.
- [CIMD - draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02), expires 7 January 2027. The unversioned IETF page resolved to revision 02. Relevant requirements include HTTPS client IDs, exact returned client_id equality, no private/shared secret material, no fetch redirects, and the standard `client_id_metadata_document_supported` discovery flag.

Other normative/profile references reviewed:

| Reference | Revision / use |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Final, incorporating errata set 2; code flow, ID token validation, UserInfo subject binding, nonce, max_age/auth_time, private_key_jwt. |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Final, incorporating errata set 2; exact issuer and discovered HTTPS endpoints/JWKS. |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | January 2025 OAuth security BCP; redirect, PKCE, CSRF and mix-up protections. |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | September 2015; S256 PKCE and the published challenge test vector. |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | May 2015; short-lived asymmetric JWT client assertion. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | February 2020 JWT BCP; algorithm/type/trust-domain separation. |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) | May 2015; JWT claim definitions. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) | May 2015; public JWK/JWKS. |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) | September 2015; canonical SHA-256 public JWK thumbprints for client key identifiers. |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) | July 2015; client registration metadata vocabulary. No dynamic registration endpoint is required or implemented. |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) | March 2022; authorization response issuer validation. |
| [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | Final; reviewed, but provider logout is outside this release's local-session logout behavior. |
| [WordPress plugin security](https://developer.wordpress.org/plugins/security/), [authentication cookies](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/), [password verification](https://developer.wordpress.org/reference/functions/wp_check_password/) | Current WordPress APIs; nonces/capabilities, cookie sessions and local reauthentication. The installed 7.1.3 core was also inspected for single-site and multisite account removal semantics. |
| [PHP-JWT upstream](https://github.com/googleapis/php-jwt), [7.2.1 release](https://github.com/googleapis/php-jwt/releases/tag/v7.2.1) | Current Packagist stable release on the check date. Explicit algorithm/Key objects, ES256 OpenSSL support, namespace-isolated bundling. Runtime does not support PS256 because that would add another crypto dependency. |

The Composer package remains `firebase/php-jwt`; its upstream repository redirects to `googleapis/php-jwt`. Version **7.2.1**, commit `0501f5729b9e2448516674aff07c7d1727869b8e`, is pinned. Composer's advisory audit reported no known vulnerabilities for this lockfile on the check date. This is not proof of absence of vulnerabilities.

## RESOAuth observation

Direct HTTPS GET succeeded, including a second fetch using the plugin's native DNS-pinned cURL transport. An initial browser-research fetch and a Python default-user-agent fetch failed; these were not treated as successful checks. The evidence below comes from successful direct HTTPS responses, not assumptions about those failures.

Discovery: [live URL](https://auth.resoauth.cloud/.well-known/openid-configuration), [saved public JSON](evidence/resoauth-discovery-2026-10-16.json).

| Item | Actual advertised value |
| --- | --- |
| Exact issuer | `https://auth.resoauth.cloud` |
| Authorization endpoint | `https://auth.resoauth.cloud/authorize` |
| Token endpoint | `https://auth.resoauth.cloud/token` |
| Public keys | `https://auth.resoauth.cloud/.well-known/jwks.json` |
| UserInfo | `https://auth.resoauth.cloud/userinfo` |
| End session | `https://auth.resoauth.cloud/logout` (not used by this plugin) |
| Response / grant types | `code` / `authorization_code` |
| Response modes | `query`, `form_post` (plugin uses query) |
| Scopes | `openid`, `email`, `profile` |
| PKCE | `S256`; vendor `urn:sag:require_pkce: true` also present but not consumed |
| ID token signing algorithms | `ES256` |
| Client authentication methods | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`; plugin uses only private_key_jwt |
| Client assertion signing algorithms | `ES256`, `ES384`, `RS256`, `PS256`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`; plugin uses only ES256 |
| Subject types | `public`, `pairwise` |
| Authorization response issuer | `authorization_response_iss_parameter_supported: true` |
| CIMD | Standard `client_id_metadata_document_supported` absent. Vendor `urn:sag:client_registration` reports `cimd: true`, `static: false`, `store: s3`. This vendor field is recorded only; runtime does not interpret it. |
| HTTP caching | Discovery and provider JWKS responses: `Cache-Control: public, max-age=300` |

The [saved JWKS](evidence/resoauth-jwks-2026-10-16.json) contained five public EC/P-256 ES256 keys with `kid` values. This confirms public-key retrieval and document shape, not ID token issuance or login success.

**Unknown/unverified:** actual CIMD acceptance for this WordPress client, accepted redirect origin relationships, localhost HTTPS acceptance, inline JWKS acceptance, authorization-server cache bounds for **client** metadata/keys, end-user consent/claims, pairwise subject derivation, and a complete real user login. Provider JWKS cache headers do **not** tell us how long the provider caches this client's keys. No external user credentials were used and no real account was created or linked.

**Token audience diagnostic, 16 October 2026:** The [provider's public implementation](https://github.com/RESOAuth/smart-access-gateway/blob/main/src/oauth/clientauth.js) checks a `private_key_jwt` assertion's `aud` against the issuer URL. Two otherwise equivalent requests to the live token endpoint used deliberately invalid authorization codes and valid signed client assertions for this plugin's metadata. With `aud` set to the token endpoint URL, the response was HTTP 401 `invalid_client` and identified the audience; with `aud` set to the issuer, it advanced to HTTP 400 `invalid_grant` for the dummy code. No real code, token or user credential was used. This confirms client-authentication compatibility for the issuer audience, not a complete login. OIDC Core says the token endpoint audience **SHOULD** be used; [RFC 7523 section 3](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) permits the authorization server to define its own exact audience string. The plugin exposes that choice as a generic advanced setting.

## Default Dynamic CIMD proxy observation

On 19 October 2026, a direct HTTPS GET to the new [default service](https://dynamic-cimd.resoauth.cloud/cimd/e30) returned status 200, JSON content type, and `client_id` equal to that exact fetch URL. The `e30` example represents `{}` and is not a complete usable client document. A second round trip sent a generated public metadata fixture with two public EC keys and an HTTPS localhost callback, omitting `client_id`. The service returned every field unchanged and inserted the exact requested URL as `client_id`. [Saved request, response and headers](evidence/dynamic-cimd-roundtrip-2026-10-19.json). No private key, token, password or access policy was sent. The response advertised `Cache-Control: public, max-age=31536000, immutable`, which applies to that immutable proxy URL, not to the hosted provider's cache of client metadata or keys. Provider acceptance and a live end-user login remain unverified.

The default template is `https://dynamic-cimd.resoauth.cloud/cimd/%s`; it is a separate service from the [RESOAuth hosted Smart Access Gateway](https://sag.resoauth.dev/hosted). The gateway's [privacy notice](https://sag.resoauth.dev/hosted/privacy-notice) and [terms of service](https://sag.resoauth.dev/hosted/terms-of-service) cover the hosted sign-in service. Local settings use Dynamic CIMD for client metadata. Self-hosted document/JWKS serving does not use a metadata proxy.

## Previous proxy observation

A direct HTTPS GET to [the supplied transport example](https://path2json.olliejc.workers.dev/e30/add_client_id/client.json) returned status 200, JSON content type, and a document containing exactly the requested URL as `client_id`. `e30` decoded to `{}`. That response is a transport demonstration, not usable complete client metadata. [Saved response](evidence/proxy-example-2026-10-16.json).

A second request encoded a complete generated **public** Simple OAuth CIMD Access metadata fixture, including two public EC keys and an HTTPS localhost callback, without client_id. The returned JSON preserved every supplied field and inserted client_id equal to the full requested URL. [Exact requested URL and response](evidence/proxy-roundtrip-2026-10-19.json). No private key, token, password or access policy was sent. This did not test an authorization server's acceptance of that document.

Both responses advertised `Cache-Control: public, immutable, max-age=86400, s-maxage=86400`. This concerns the immutable proxy document, not RESOAuth's own cache bounds. The service was available for these checks; future availability, URL-length limits and provider redirect-policy compatibility are not guaranteed. The configured template determines the service. Self-hosted document/JWKS serving does not call or depend on this proxy.

## Tested provider profiles

| Profile | Result |
| --- | --- |
| Synthetic OIDC/CIMD provider, ES256 ID tokens, ES256 private_key_jwt, query response, S256, RFC 9207 issuer | Baseline WordPress HTTP/browser login, cancellation/failure/recovery, test login and local logout passed; 0.0.3 email-based account selection passed the WordPress suite. |
| Synthetic OIDC/CIMD provider with RS256 ID tokens and separate ES256 client keys | Signed-token verification passed with a 2048-bit provider RSA key. |
| Synthetic UserInfo profile | Bearer request only to the discovered endpoint; exact sub matching and conflicting email-claim rejection tests passed. |
| Synthetic rotated provider JWKS | One refresh on unknown kid; subsequent refresh throttled. Invalid algorithm/client-key substitution refused. |
| Synthetic inline CIMD proxy | Actual generated document decoded/validated in fixture; code, redirect, PKCE and assertion binding verified at the mock token endpoint. |
| Live RESOAuth | Discovery and JWKS fetched. Full end-user interoperability unverified. |
| Live RESOAuth Dynamic CIMD proxy | Example and full public-document round trips passed. Provider acceptance unverified. |
| Previous supplied path2json proxy | Example and full public-document round trips passed on 16 October 2026. It is no longer the default. |

See [TESTING.md](TESTING.md) for the executable test inventory and environment. No OpenID conformance certification or independent penetration test is claimed.
