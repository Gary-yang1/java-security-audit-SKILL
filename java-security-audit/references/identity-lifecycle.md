# Identity Lifecycle and Capability-Flow Review

Use this reference for applications that authenticate users, manage accounts, expose SSO or recovery, bind external identities, import or synchronize users, or treat identifiers and tickets as trust inputs.

## Contents

- Mandatory lifecycle matrix
- Identifier and capability closure
- Global fail-open expansion
- External identity binding
- Account creation and activation
- Session, token, and cross-service trust
- Completion gate

## Mandatory Lifecycle Matrix

Inventory each applicable stage before prioritizing findings:

| Stage | Typical operations |
|---|---|
| Discovery | username, email, phone, employee number, UUID, subject, tenant, existence check |
| Enrollment | registration, invitation, provisioning, self-service signup, pending record |
| Verification | email or SMS code, password, MFA, external-provider assertion, device approval |
| Binding | match, link, auto-bind, merge, recovery binding, external subject mapping |
| Approval | approve, reject, activate, disable, unlock, role or group assignment |
| Credential lifecycle | password set or reset, recovery code, API key, MFA seed, device credential |
| Session lifecycle | login, SSO callback, token exchange, ticket minting, session bootstrap, logout |
| Administration | create user or admin, import, bulk update, synchronization, impersonation |
| Deprovisioning | disable, delete, revoke, unbind, terminate sessions, remove roles |

For every stage, record the public route or trigger, active authentication mechanism, role and tenant requirement, attacker-controlled identity fields, sensitive response fields, state-changing sink, and configuration gates.

Do not equate a pending registration row with an active user. Trace approval, password creation, status flags, group or role assignment, notification, and login eligibility separately.

## Identifier and Capability Closure

Treat these values as capabilities when downstream code relies on them:

- UUID, user ID, account ID, tenant or company ID, client ID, external subject or union ID;
- password-reset code, authorization code, invitation code, activation link;
- access or refresh token, SSO ticket, session cookie, device token, QR polling handle;
- role or group ID, approval state, verified flag, tenant context.

For each required value, answer:

1. Is it secret, merely unique, predictable, or public by design?
2. Where is it created?
3. Where can it be returned, redirected, logged, cached, messaged, exported, or embedded?
4. Can an unauthenticated or lower-privilege actor obtain it through lookup, enumeration, matching, import, callback, error behavior, or another service?
5. Is it bound to subject, tenant, client, audience, purpose, TTL, and one-time use?
6. What downstream operation incorrectly treats possession as authority?

If a finding requires knowing an identifier, token, or ticket, do not finalize it until these questions are answered. Search explicit response construction and DTO serialization. A field declaration alone is not proof of disclosure.

Candidate discovery:

    rg -n -g '*.java' 'map\.put\(|setMapParam\(|setUuid\(|setUserId\(|setAccountId\(|setTenantId\(|getUuid\(|userId|accountId|tenantId|companyUuid|ticket|token|code|redirect' .

## Global Fail-Open Expansion

When a global or broad authentication control fails open, do not audit only annotated or obviously sensitive methods.

1. Determine exact path and dispatch coverage.
2. Mark every covered route anonymous until another active control is proven.
3. Re-run the route ledger for sensitive outputs, state changes, and trust transitions.
4. Check unannotated business methods and custom annotations whose enforcement may be inactive.
5. Record configuration gates as conditions instead of dropping the candidate.

Business routes often use names such as match, bind, flow, callback, poll, authorize, exchange, approve, issue, provision, import, or sync.

## External Identity Binding

Do not trust client-submitted provider identifiers or profile attributes merely because their names resemble authoritative claims.

Prove:

- the application obtains a provider-issued code, assertion, or token over a protected back channel;
- signature, issuer, audience, nonce or state, redirect URI, expiry, and replay are checked as applicable;
- matched profile attributes come from the verified provider response;
- the external identity is bound to the same local user and tenant being modified;
- matching rules do not return internal identifiers before verification;
- binding, auto-match, and merge cannot create a session or reset credentials without completing the intended proof.

A configuration switch such as automatic binding changes exploitability, not the trust analysis. Report it as an explicit runtime condition.

## Account Creation and Activation

Search beyond methods named createUser:

    rg -n -g '*.java' -g '*.xml' 'register|regist|sign.?up|invite|enroll|provision|approve|activate|import|sync|insert.*user|insert.*account|is_admin|account_status|role|group' .

Trace:

    request, message, or import row
    → verification and duplicate checks
    → tenant selection
    → pending or active user insert
    → credential creation
    → role, group, or administrator assignment
    → activation and notification
    → login eligibility

Verify role authorization at every transition. Authentication alone is insufficient for user or administrator creation, approval, role assignment, import, or impersonation.

Check bulk import and directory synchronization for missing tenant context, null or default tenant behavior, caller-controlled organization fields, duplicate handling, partial transactions, default passwords, and anonymous reachability.

## Session, Token, and Cross-Service Trust

Build producer-consumer pairs for every trust artifact:

| Artifact | Producer | Store or transport | Consumer | Required binding |
|---|---|---|---|---|
| Session cookie | login or SSO | browser or cache | filters and controllers | user, tenant, device, expiry |
| Ticket or code | portal or auth service | redirect, cache, or message | console or token endpoint | client, redirect, purpose, TTL, one-time use |
| JWT or token | issuer | header or cookie | API or gateway | algorithm, issuer, audience, subject, scope, expiry |
| Reset or invite code | recovery or admin | email, SMS, or cache | reset or activation | user, purpose, TTL, one-time use |

Across modules, compare key identifiers and formats without printing secret values. Confirm cache namespace, database index, cookie domain, key identity, issuer or audience, serialization, TTL, atomic consumption, and replay behavior.

Look for a service that accepts a user or tenant ID from a request, mints a trusted artifact, and causes another service to create a session without re-authentication or role validation.

## Completion Gate

Do not close the identity review until:

- every lifecycle stage is marked reviewed, not applicable, conditional, or unresolved;
- every identifier, token, or ticket precondition has an acquisition analysis;
- every active user or administrator creation path is distinguished from pending records;
- every broad fail-open control has triggered a covered-route rescan;
- every external binding result is traced to provider-verified evidence;
- every cross-service trust artifact has a producer-consumer record;
- discovery output was reviewed completely rather than silently truncated.
