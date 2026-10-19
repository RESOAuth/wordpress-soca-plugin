# Release history

## 0.1.1

- Reviewed the WordPress.org submission guidance and trimmed development documentation and evidence from the installable ZIP; the source archive retains them.
- Prepared database table identifiers with WordPress `%i` placeholders and tightened callback query and authorization-code validation.
- Unslashed query values at WordPress request boundaries while preserving exact OAuth values for protocol checks.
- Kept scheduled maintenance local while upstream login is disabled and clarified when enabled sites contact the configured provider and metadata proxy.

## 0.1.0

- Prepared the plugin header, WordPress.org listing, author and package metadata for the first directory submission.
- Moved detailed operating instructions to the guide, linked the hosted provider's docs and policies, and changed the default development metadata proxy to RESOAuth Dynamic CIMD. Saved proxy settings remain unchanged on upgrade.
- Moved outbound HTTPS requests to the WordPress HTTP API, retaining public-address validation, cURL DNS pinning and strict response handling. Login policy and OIDC validation remain as in 0.0.5.

## 0.0.5

- Used a direct OIDC callback without a SOCA transaction cookie. Matched the User-Agent at start and callback while retaining one-time state, PKCE, nonce, token validation, verified-email account selection and redacted audit events.

## 0.0.4

- Distinguished missing and mismatched browser cookies in redacted audit events, retained the login reference across transaction failures, and reported whether the start and callback hostnames matched.

## 0.0.3

- Selected accounts by the current verified email on every login, removed subject binding from the login path, and added redacted step, reason and reference diagnostics.

## 0.0.2

- Used SOCA names consistently across recovery, diagnostics and maintenance, retained legacy compatibility, and defaulted the login button to “Continue with SSO”.

## 0.0.1

- Initial SOCA release: OIDC code flow with PKCE, CIMD metadata, verified-email access policy, identity binding, public key rotation, diagnostics and local recovery.
