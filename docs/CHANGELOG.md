# Release history

## 0.3.0 (unreleased)

- Bind each ten-minute transaction to its initiating browser using an independent Secure, HttpOnly, SameSite=Lax cookie; retain encrypted WordPress transients and atomic replay checks.
- Replace email-based account selection with encrypted, unique issuer/subject associations. Add explicit administrator linking/revocation and conservative provisioning rollback. Existing users require approved links.
- Require an admitted, fresh test login before ordinary SSO becomes available. Bind evidence to candidate configuration and metadata; preserve the operator session and prevent test-side account writes.
- Add deployment overrides and locks for every supported setting, shared validation, stale form rejection, WP-CLI configuration and operator-bound test URLs. Emergency disable and deactivation invalidate pending flows and activation evidence.
- Support exact and leading `*.` domain rules, platform branding/privacy defaults, public metadata overrides and explicit proxy payload/URL limits.
- Publish a per-ID shared requirements review with remaining security, interoperability and operational gaps.

## 0.2.0

- Standardized the PHP and vendored JWT namespaces, hooks, options, transients and configuration constants under SOCA, and removed pre-release compatibility paths.
- Replaced the custom transaction table with encrypted, expiring WordPress transients. Kept database advisory locks for one-time callback consumption and concurrent account/key operations.
- Moved account lookup to WordPress user APIs and removed custom-table setup and uninstall schema changes.
- Used `wp_safe_redirect()` for the validated authorization host, exited after redirect, and validated server input at its read boundary.

## 0.1.1

- Reviewed the WordPress.org submission guidance and trimmed development documentation and evidence from the installable ZIP; the source archive retains them.
- Prepared database table identifiers with WordPress `%i` placeholders and tightened callback query and authorization-code validation.
- Unslashed query values at WordPress request boundaries while preserving exact OAuth values for protocol checks.
- Kept scheduled maintenance local while upstream login is disabled and clarified when enabled sites contact the configured provider and metadata proxy.

## 0.1.0

- Prepared the plugin header, WordPress.org listing, author and package metadata for the first directory submission.
- Moved detailed operating instructions to the guide, linked the hosted provider's docs and policies, and set the default development metadata proxy to RESOAuth Dynamic CIMD.
- Moved outbound HTTPS requests to the WordPress HTTP API, retaining public-address validation, cURL DNS pinning and strict response handling. Login policy and OIDC validation remain as in 0.0.5.

## 0.0.5

- Used a direct OIDC callback without a SOCA transaction cookie. Matched the User-Agent at start and callback while retaining one-time state, PKCE, nonce, token validation, verified-email account selection and redacted audit events.

## 0.0.4

- Distinguished missing and mismatched browser cookies in redacted audit events, retained the login reference across transaction failures, and reported whether the start and callback hostnames matched.

## 0.0.3

- Selected accounts by the current verified email on every login, removed subject binding from the login path, and added redacted step, reason and reference diagnostics.

## 0.0.2

- Used SOCA names consistently across recovery, diagnostics and maintenance, and defaulted the login button to “Continue with SSO”.

## 0.0.1

- Initial SOCA release: OIDC code flow with PKCE, CIMD metadata, verified-email access policy, identity binding, public key rotation, diagnostics and local recovery.
