# Shared SOCA requirements assessment

Assessed on **21 October 2026 (Europe/London)** against the local
`soca-plugins/requirements.md` at commit
[`60ea4db827457b4a4a7b11d79e86b654612a75e1`](https://github.com/RESOAuth/soca-plugins/blob/60ea4db827457b4a4a7b11d79e86b654612a75e1/requirements.md).
The assessed file's SHA-256 is
`d2db3ee4d66717152c79af1863ea6d6ed117bb20ac5875bac723e38c73c45b85`.
The [shared requirements](https://github.com/RESOAuth/soca-plugins/blob/main/requirements.md)
remain the target; this assessment does not weaken them.

Every row below assesses **0.3.0, unreleased**, in the same commit as this document,
against base `654d517`. The result date is **21 October 2026** for every row.
“Partial” means some required behaviour or evidence is missing; “planned” means
there is no implementation. Source review alone is not a successful live login.

| ID | Status | Versioned evidence and result | Remaining gap |
| --- | --- | --- | --- |
| F-01 | Partial | [Provider](../simple-oauth-cimd-access/includes/Provider.php), [protocol tests](../tests/protocol.php): pinned issuer, capability refusal, RESOAuth defaults. | One provider per site; no simultaneous isolated profiles. Live acceptance unverified. |
| F-02 | Supported | [Browser tests](../tests/browser.cjs), [protocol tests](../tests/protocol.php): code, S256, independent state/nonce, exact callback, ES256 private_key_jwt, copied-callback refusal. | Restricted to the declared single-provider query-response profile. |
| F-03 | Partial | Protocol and browser tests: signatures, issuer, audience, nonce, times, response issuer, UserInfo subject/conflict refusal, fresh test authentication. | Configurable assurance and ordinary-login reauthentication policy. |
| F-04 | Partial | [Metadata](../simple-oauth-cimd-access/includes/Metadata.php), protocol tests: generated identity, WordPress name/home/icon/privacy defaults, overrides, public document checks. | WordPress has no standard terms-page setting; explicit tos_uri is needed. Packaged public reachability and provider activation remain deployment checks. |
| F-05 | Partial | Protocol tests: default/custom proxy, exact returned ID, deterministic encoding without client_id, overlapping two-key payload, payload/URL refusal. Browser: synthetic proxy login. | Provider/proxy URL limits are unconfirmed; no reset button; live proxy login unverified. |
| F-06 | Supported | Protocol and WordPress tests: inline/URI public keys, private-material refusal, no admission rules in public metadata. [Privacy disclosure](../simple-oauth-cimd-access/readme.txt). | Provider permission must be confirmed for each mode. |
| F-07 | Partial | [Security](SECURITY.md), rotation tests: bounded old signing-key retention and transaction snapshots. Candidate fingerprints include client metadata. | Inline document/key changes require a fresh admitted test and explicit pairwise-subject recovery; uninterrupted identity migration is not implemented. |
| F-08 | Partial | WordPress/protocol tests: stable key IDs, non-autoloaded authenticated encryption, per-site secret context. | External/non-exportable key management and tested backup/lost-key recovery. |
| F-09 | Partial | Protocol rotation vectors: publication, warm-up, retained retiring keys, delayed ticks and fixed retirement deadlines. | Inline key-set changes invalidate activation evidence; external mirrors need separate automation. No complete emergency key-revocation workflow or fault-tested worker promotion. |
| F-10 | Partial | Protocol ES256 and RS256 signature tests; ES256/P-256 client default and independent ID-token pin. | ES384/512, PS256/384/512, fully specified EdDSA and ML-DSA profiles/vectors. No silent fallback is enabled. |
| F-11 | Partial | Protocol tests: bounded cache expiry, unknown-kid/signature retry and 60-second refresh gate. | Explicit provider-key revocation signalling and broader outage/fault evidence. |
| F-12 | Partial | Protocol/WordPress/browser tests: exact and leading *. domains, nested labels, invalid rules, deny precedence, boolean verified email, preview. Startup revalidates saved/deployment rules. | Dedicated sensitive-account controls beyond explicit identity approval and site membership. |
| F-13 | Supported | [WordPress](../tests/wordpress.php) and [multisite](../tests/multisite.php) tests: links select one eligible account, email-only/changed-subject refusal, changed email preserves identity, roles/capabilities preserved, removed/spam/nonmember refusal. | Host extensions with additional account-disable semantics need integration. |
| F-14 | Partial | WordPress tests: opt-in Subscriber creation, random password, link-failure rollback. [Concurrency](../tests/concurrency.py): one account and identity owner. | Account/link writes are compensating operations, not a database transaction; process termination or external hook side effects can leave partial state. Role is fixed to Subscriber. |
| F-15 | Partial | WordPress tests: provider role claims cannot elevate; existing local roles preserved. Link revocation destroys local sessions. | Claim mappings/ceilings, independent elevation workflow and admission-revocation propagation to existing sessions. |
| F-16 | Partial | WordPress/concurrency tests: encrypted unique issuer/subject associations, explicit admin approval, conflicting-link refusal, unlink tombstones and session revocation. | Self-service local reauthentication and a dedicated association inventory/recovery UI. Audit is not tamper-evident. |
| F-17 | Partial | WordPress tests: changed subject refuses email relinking; changed email retains linked account. Explicit unlink/reapproval supported. | Guided, independently verified issuer/client/pairwise-subject migrations. |
| F-18 | Planned | Source review: existing profile fields are preserved; no claim mapping is performed. | Profile mappings, per-field policies, preview and validation. |
| F-19 | Planned | Source review: test result contains policy outcome only; routine logs omit claims/tokens. | Opt-in, encrypted, operator/transaction-scoped claim inspection and expiry. |
| F-20 | Partial | [Configuration](CONFIGURATION.md), [deployment tests](../tests/deployment.php), browser: complete supported settings in code/CLI/UI, deployment locks, stale form refusal, candidate testing and side-effect-free test login. | Revision history/automatic rollback, comprehensive accessibility evidence and mapping preview once mapping exists. Browser authentication remains necessary for a real operator test. |
| F-21 | Partial | Browser tests: WordPress sessions/local logout, confined return URLs, automatic redirect recovery. | Configurable SSO session policy and advertised RP/back-channel logout. |
| F-22 | Partial | [Emergency tests](../tests/emergency.php), browser: local recovery, constant override, ordinary/test in-flight refusal and latched invalidation. | Strong local MFA is host-managed; full upgrade/recovery exercises remain. Deployment must ensure every worker observes the constant. |
| F-23 | Partial | Browser/multisite tests and [uninstall](../simple-oauth-cimd-access/uninstall.php): scoped state, deactivation invalidation, explicit data erasure, preserved users/permissions. | Comprehensive lifecycle/migration/rollback testing. Existing sessions survive disable/deactivation. |
| F-24 | Supported | Provider/source review and token-exchange tests: no offline scope by default, codes/access/ID tokens used only within the request, no refresh-token retention. | Operators must request only scopes needed by their deployment. Delegated access is outside this profile. |
| F-25 | Supported | WordPress/concurrency/browser tests: encrypted ten-minute transients, independent browser-secret cookies, atomic single use, replay/copy refusal, parallel tabs, new WordPress authentication token. | Additional cookie justified below; all browser coverage uses Chromium. |
| N-01 | Partial | [Security](SECURITY.md), protocol negative tests, Psalm/WordPressCS/Semgrep checks. | Independent threat-model review and a defined cryptographic dependency update process. |
| N-02 | Partial | Http source/protocol tests: DNS pinning, all-address rejection, TLS checks, no redirects, response/deadline bounds. | Complete native IPv6/mixed-DNS/slow-response/egress integration matrix. |
| N-03 | Partial | Encrypted keys/transactions/links, no token retention or telemetry, public service disclosure and redacted audits. | Automatic link/report retention policy, backup deletion and verified infrastructure access-log redaction. |
| N-04 | Partial | Multisite and concurrent-process suites pass; routine cache/key overlap tested. | Failover/restore, rolling upgrades, durable revocation after backup restore and published recovery objectives. |
| N-05 | Partial | Source/protocol tests: fixed transaction/rate/cache/response bounds and refresh throttling. | Latency/throughput/resource budgets, sustained abuse/load evidence and aggregate transaction cleanup bounds. |
| N-06 | Partial | Browser UI checks, redacted failure references, Site Health and status commands. | WCAG 2.2 AA audit, tamper-evident audit storage, retention by time and security/availability metrics. |
| N-07 | Partial | Deterministic package builder, pinned Composer runtime dependency, dependency audit and security CI. | Immutable workflow/container references, signed provenance, formal SBOM, response SLA and release-blocking vulnerability policy. |
| N-08 | Partial | [Test record](TESTING.md): protocol, WordPress, browser, concurrency, multisite, static checks. | Live logins in both metadata modes, broader browsers/platforms, conformance suite, independent review, packaged fault/recovery coverage. |
| N-09 | Partial | This revision/digest and per-ID assessment; [configuration](CONFIGURATION.md), limits below, fixtures and [dated test record](TESTING.md). | Live provider profiles, measured performance/revocation budgets and acceptance results for the planned capabilities. |

## Tested profiles and protected surfaces

The protected entry points are the standard WordPress login button, optional
ordinary-login redirect and the `soca_start`/`soca_callback` actions. Local login,
password recovery and logout remain WordPress-managed. REST/API authorisation,
other grants and delegated access are outside this profile.

| Metadata mode | Provider/profile | Result on 21 October 2026 |
| --- | --- | --- |
| Self-hosted | Synthetic ES256 and RS256 token validation; public metadata/JWKS generation | Protocol tests pass. A complete current self-hosted browser/provider login has not been run. |
| Proxy, inline JWKS | Synthetic ES256 provider, code/query/S256/private_key_jwt | Browser login, candidate test, cookie/replay failures and recovery pass. |
| Default Dynamic CIMD | Public document only | Historical 19 October round trip in [standards evidence](STANDARDS.md); no current real provider login. |
| RESOAuth | Live discovery/JWKS only | Historical observations in STANDARDS.md. End-user login in both modes remains unverified. |

## Security limits and retention

| Item | Default / fixed bound | Operator choice and implications |
| --- | --- | --- |
| Transaction | 600 seconds; encrypted WordPress transient; single database-locked consumer | Fixed. Per-transaction `__Host-soca_tx_*` cookie, 256-bit independent secret, Secure/HttpOnly/SameSite=Lax, host-only, path /; deleted after a consumed callback, otherwise expires. The extra cookie supplies binding absent from logged-out WordPress sessions. No browser JavaScript storage. |
| Client assertion | 60 seconds; fresh 256-bit jti | Fixed ES256/P-256; issuer audience by default, token endpoint may be selected explicitly. |
| ID token | 60 seconds clock tolerance; maximum exp-iat 86400 seconds | Issued no earlier than transaction start minus tolerance. Test login requires fresh auth_time. |
| Rotation | Target 604800 seconds; hourly scheduler | Provider cache window 24 hours, allowed 1–168 hours. Unknown provider cache bound must be established by the operator. Delays extend overlap safely. |
| Retiring key | Cache window plus 720 seconds after actual promotion | Covers 600-second transaction, 60-second assertion and 60-second skew. A reduced setting cannot shorten an existing retirement promise. |
| Documents/caches | Public CIMD/JWKS 300 seconds; discovery/provider JWKS at most 3600 seconds | Honour shorter max-age/Age and no-cache/no-store; no stale trust on failure. Publication reused for at most 300 seconds. |
| Proxy encoding | 8192 UTF-8 JSON bytes; 12288 client-ID URL bytes | Fixed local ceilings, including two overlapping public keys; actual provider/proxy limits may be lower and must be checked. Fixed field order, sorted public keys, unescaped Unicode/slashes, no whitespace or client_id in encoded JSON. |
| Network | 12-second request timeout; 5-second connect timeout; 256 KiB body; 32 KiB headers; zero redirects | DNS resolver wall-clock behaviour remains platform-dependent. HTTPS callback required even on localhost. |
| Rules | 200 entries and 32000 input bytes per list; domain <=253 bytes; email <=254 bytes | Exact public ASCII/punycode DNS names or one leading *. for domain lists; no single-label suffixes. |
| Abuse | 30 starts per server-observed IP per 600 seconds; one forced JWKS refresh per issuer/URL per 60 seconds | Shared reverse proxies share a limit. Add host/edge rate controls; aggregate storage is not globally capped. |
| Diagnostics/audit | Policy-only operator test result 600 seconds; CLI test ticket 600 seconds and single use; last 100 redacted audit entries | No claim inspection is implemented. Activation evidence lasts until the candidate fingerprint changes or is invalidated. Audit is not tamper-evident or time-expired. |
| Sessions/revocation | Native WordPress lifetime; unlink destroys all sessions for the selected account | Disable/deactivation stop new SSO and invalidate pending flows, retaining existing WordPress sessions. Admission edits apply on the next login; no bounded existing-session policy propagation is claimed. |
| Identity records | Encrypted active links and revocation tombstones retained until explicit erasure | Deleted/removed users do not silently reprovision through their old links. Uninstall erases associations only with SOCA_ERASE_DATA=true; protect/reconcile backups. |

Inline key-set changes alter the client ID and invalidate the candidate test
fingerprint. This deliberately requires an operator test before further ordinary
SSO; it does not meet unattended, uninterrupted inline-proxy rotation. Use stable
JWKS indirection for production where supported. Never recover pairwise subjects
by matching mutable email claims.
