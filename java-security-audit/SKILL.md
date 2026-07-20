---
name: java-security-audit
description: Audit Java Web, Spring Boot, SSM, and microservice source code or packaged JAR/WAR artifacts for evidence-backed authentication bypass, identity-lifecycle flaws, identifier disclosure, session or token minting, user or administrator creation, authorization and tenant failures, injection, RCE, SSRF, unsafe deserialization, file vulnerabilities, dependency risks, cryptographic weaknesses, and exposed secrets. Use when reviewing Java source, decompiled code, executable artifacts, security findings, or preparing a security audit report.
---

# Java Security Audit

Perform a source-to-sink audit that distinguishes dangerous code from exploitable behavior. Treat the packaged artifact and effective runtime configuration as stronger evidence than project defaults or decompiler output.

## Core Rules

- Use `rg` and `rg --files` for discovery. Preserve the target and keep static review read-only.
- Do not label a keyword match as a vulnerability. Confirm input control, data flow, component registration, route reachability, authorization, effective configuration, and sink behavior.
- Do not stop at a sink whose exploitability depends on an identifier, token, ticket, tenant, role, or workflow state. Reverse-trace how an attacker could obtain or influence every required capability.
- Separate source-level existence from deployment-level exploitability. Record contradictions instead of forcing a conclusion.
- Redact secrets in notes and reports. Identify their locations and types without copying live values.
- Perform dynamic validation only within explicit authorization. Prefer runtime mapping inspection and harmless proofs over weaponized payloads.
- Report only the severities requested by the user. Do not inflate ratings by chaining unrelated findings unless the chain is demonstrably reachable.
- Treat route coverage as a deliverable. Do not claim a full external-entry audit from sampled searches or truncated output.

## Resource Routing

- Read [references/sinks.md](references/sinks.md) when locating or triaging dangerous sources and sinks.
- Read [references/spring-security.md](references/spring-security.md) for Spring component scanning, route registration, filter chains, method authorization, gateway prefixes, profiles, and configuration precedence.
- Read [references/identity-lifecycle.md](references/identity-lifecycle.md) whenever the application authenticates users, exposes SSO or recovery, binds external identities, imports or synchronizes accounts, or uses identifiers and tickets as authorization inputs.
- Read [references/decompilation.md](references/decompilation.md) when the target includes JAR/WAR files, nested Spring Boot libraries, or decompiled sources.
- Run `scripts/inventory.sh <path>` for a deterministic, read-only first-pass inventory. Inspect the script before adapting it to an unusual layout.
- Run scripts/identity-surface.sh with a source path and optional output file for Java web applications with identity or account functionality. Review large output from a temporary file in chunks instead of truncating unreviewed candidates.

## Workflow

### 0. Establish Scope and Constraints

Record:

- source directories and executable artifacts in scope;
- artifact hashes, application version, Java/Spring versions, and build type;
- requested severity threshold and report format;
- whether runtime, database, gateway, and deployment configuration are available;
- whether dynamic validation is authorized and which hosts/actions are allowed.

Do not infer production exposure from source code alone.

### 1. Inventory the Actual Application

Run the inventory script, then identify:

- main/start classes, modules, Controllers, Filters, Interceptors, security configurations, scheduled jobs, message consumers, and management endpoints;
- Maven/Gradle metadata and the versions actually packaged under `BOOT-INF/lib`, `WEB-INF/lib`, shaded JARs, or container layers;
- application profiles, external configuration hooks, Kubernetes manifests, gateway routes, servlet context paths, and reverse-proxy rewrites;
- trust boundaries: HTTP, messaging, scheduled tasks, file import, database records later interpreted as code/configuration, and service-to-service calls.
- identity boundaries: account lookup, registration, invitation, approval, activation, recovery, MFA, external binding, SSO or token exchange, session bootstrap, user or administrator creation, import, synchronization, and deprovisioning.

For executable artifacts, follow `references/decompilation.md` before accepting source-only conclusions.

### 2. Discover Candidate Sources and Sinks

Use `references/sinks.md` to search by category. Prioritize sinks capable of code execution, authentication bypass, cross-tenant access, arbitrary SQL, SSRF, unsafe file writes, or secret disclosure.

Treat search hits as candidates. Record the dangerous argument and owning method, not merely the matching line.

For web applications, create a route ledger before prioritizing findings:

| Entry point | Auth decision | Attacker-controlled identity fields | Sensitive response fields | State-changing sink | Tenant/object check |
|---|---|---|---|---|---|

Include every externally reachable controller method, RPC endpoint, GraphQL resolver, WebSocket handler, and relevant message consumer. Mark entries reviewed, conditional, inactive, or pending. Do not silently omit low-signal business routes.

### 2A. Close Capability Preconditions

For every candidate, trace source to sink as described below, then reverse-trace each required capability:

    required UUID / account ID / tenant ID / reset code / token / ticket / role / workflow state
    ← response, redirect, cookie, log, cache, message, database, QR code, callback, import, or predictable generation
    ← attacker action needed to obtain or influence it

Treat sensitive outputs as future sources. An internal identifier may be low impact alone but critical when another reachable method treats possession as proof of identity or authority. Merge only demonstrably connected steps and state configuration or deployment conditions explicitly.

### 3. Trace Source → Transform → Sink

For each candidate, trace both directions:

```text
external source
→ framework binding / deserialization
→ validation, normalization, allowlist, authorization
→ service/manager/DAO calls
→ dangerous sink
→ observable security impact
```

Include indirect sources such as database fields, uploaded configuration, message bodies, cache data, headers, JWT claims, and workflow variables. Determine whether an attacker can create or modify the stored value before treating it as trusted.

Evaluate every defense semantically:

- Is an allowlist exact and applied after decoding/canonicalization?
- Are redirects and every resolved IP revalidated for SSRF?
- Is SQL structure allowlisted rather than keyword-blocked?
- Is a file path normalized and constrained to a canonical root?
- Is a signature bound to every security-sensitive field and protected against replay?
- Does external-identity binding verify provider-issued server-side evidence, or merely trust caller-supplied email, phone, subject, union ID, employee ID, or account ID?
- Does account creation, approval, import, impersonation, or role assignment require the correct role and tenant rather than only a valid session?

### 4. Prove Component and Route Reachability

For Spring applications, read `references/spring-security.md` and verify:

- how the class becomes a Bean (`@ComponentScan`, default scan, `@Import`, auto-configuration, XML, or programmatic registration);
- whether `@Profile`, `@Conditional*`, exclusions, component indexes, or Bean conflicts change registration;
- the effective HTTP method and path after class/method mappings, context path, gateway prefix, and rewrite rules;
- whether the request reaches the expected application instance;
- whether runtime `RequestMappingHandlerMapping` or startup logs confirm the mapping when deployment access exists.

Never conclude that `com.example.*` scans only one class-package level without checking Spring's generated resource pattern and actual framework version.

### 5. Prove Authentication, Authorization, and Tenant Boundaries

Build a request-specific decision path:

```text
proxy/gateway policy
→ servlet filter chains and matcher/order selection
→ JWT/session/API-key validation
→ MVC interceptor
→ method security
→ business ownership and tenant check
```

Check default behavior when a URL has no role mapping, the permission service fails, or a tenant context is absent. Fail-open behavior is a finding only after showing the affected route can reach a sensitive operation.

Distinguish authentication from authorization. A valid token does not prove the caller may act on another user's file, workflow, tenant, role, or account.

If a broad Filter, Interceptor, SecurityFilterChain, gateway rule, or method-annotation mechanism is missing, inactive, or fail-open:

1. temporarily classify every route in its coverage as anonymous or low-trust;
2. re-review all identifier-returning and state-changing routes in that coverage;
3. inspect business-named flows such as match, bind, callback, poll, authorize, exchange, approve, activate, invite, import, and sync;
4. restore a stronger precondition only when another active control proves it.

Do not assume an authentication annotation executes. Prove its Filter, Interceptor, aspect, proxy, matcher, enabling configuration, and final decision.

### 6. Resolve Effective Configuration and Dependencies

Resolve active values across packaged defaults, profiles, external files, environment variables, JVM/command-line options, configuration centers, ConfigMaps, and Secrets. Mark values as packaged defaults when production overrides are unknown.

For multi-module and microservice systems, correlate trust producers and consumers:

- cache key names, namespaces, and database indexes;
- cookie names and domains;
- ticket, JWT, SSO assertion, API-key, and reset-token formats;
- encryption or signing key identity without printing key material;
- issuer, audience, tenant, subject, TTL, replay, and one-time-consumption semantics.

Do not assume similarly named values interoperate. Compare formats, keys, stores, and effective configuration. Do not miss a chain merely because producer and consumer live in different modules.

For dependency findings:

1. identify the version in the final artifact;
2. confirm the affected range from an authoritative advisory;
3. locate a reachable application call path;
4. verify required configuration, gadget, protocol, port, or permissions;
5. report conditional impact explicitly.

Do not promote a dependency CVE to the main report solely because a version string matches.

### 7. Apply the Finding Gate

Before assigning severity, answer every item:

| Gate | Required evidence |
|---|---|
| Attacker control | Identify who controls the value and through which boundary. |
| Complete flow | Show the relevant transforms from source to sink. |
| Ineffective defense | Explain why validation, encoding, sandboxing, or allowlisting fails. |
| Registration/reachability | Prove the Bean/job/consumer and route or trigger are active. |
| Authorization | State anonymous, low-privilege, role, tenant, or service preconditions. |
| Precondition closure | Show how required identifiers, tokens, tickets, roles, tenant context, or workflow states can be obtained or controlled. |
| Runtime conditions | State required network, filesystem, database, JVM, or dependency conditions. |
| Impact | Tie the sink to concrete confidentiality, integrity, or availability loss. |

Classify confidence separately from severity:

| Status | Meaning |
|---|---|
| Confirmed | Complete static chain and registration/reachability evidence exist. |
| High confidence | Static chain is complete; deployment mapping or effective override is unavailable. |
| Conditional | Exploitation depends on stated permissions, egress, driver, gadget, or configuration. |
| Potential/unreachable | Dangerous code exists but current registration or trigger is absent/unproven. |

Use the sink table only to prioritize investigation. Calculate CVSS from the proven preconditions and impact; do not copy a default severity from a keyword.

### 8. Validate Safely

Prefer, in order:

1. bytecode/annotation inspection;
2. unit or integration tests in an isolated local environment;
3. Bean and runtime route enumeration;
4. harmless requests with controlled callback infrastructure;
5. minimally invasive dynamic proof explicitly authorized by the user.

Avoid destructive SQL, persistent uploads, command payloads, data exfiltration, or cross-tenant access in production. If validation is not authorized, document the exact remaining uncertainty.

### 9. Produce the Report

Include for each finding:

1. identifier, title, CWE, severity, CVSS vector, confidence status;
2. affected artifact/version and exact `file:line` or archive path/class/method;
3. entry point or non-HTTP trigger;
4. complete source-to-sink data flow;
5. Bean/route/job/consumer registration evidence;
6. authentication, role, ownership, and tenant preconditions;
7. effective configuration and environmental dependencies;
8. acquisition path for every required identifier, token, ticket, tenant, role, or workflow state;
9. concrete impact and realistic attack chain;
10. non-destructive validation evidence or an explicit reason it was not performed;
11. code-level remediation, compensating controls, priority, and acceptance criteria.

Do not require a weaponized PoC. A complete static chain plus safe runtime evidence is preferable. Keep secret values redacted.

## Completion Checklist

- Reconcile source tree, packaged artifact, and deployed version.
- Produce and reconcile a route ledger for every externally reachable entry point and every critical sink candidate.
- Complete the identity-lifecycle matrix when accounts, authentication, SSO, recovery, external binding, import, or synchronization exist.
- Reverse-trace all capability preconditions, including identifiers, reset codes, tokens, tickets, roles, tenant context, and workflow states.
- Re-review every identifier-returning and state-changing route after finding a broad fail-open control.
- Correlate cross-module trust producers and consumers, including caches, tickets, cookies, keys, issuers, audiences, TTLs, and replay semantics.
- Resolve component registration and security-chain selection before claiming exposure.
- Check authorization and tenant ownership beyond authentication.
- Separate confirmed, conditional, and unreachable findings.
- Preserve full discovery output or record why candidates were excluded. Do not treat truncated terminal output as reviewed.
- Remove duplicates and chained restatements from the final count.
- Verify report severity counts, paths, links, hashes, redaction, and remediation acceptance criteria.
