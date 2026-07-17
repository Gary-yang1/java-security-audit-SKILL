# Spring Registration, Routing, and Security Review

Use this reference whenever a finding depends on whether a Spring Bean, route, filter chain, or method-security rule is active.

## Component Registration

Inspect all registration paths:

- `@SpringBootApplication` and its default package scan;
- `scanBasePackages` and `@ComponentScan`;
- `@Import`, `ImportSelector`, `DeferredImportSelector`, and registrar classes;
- XML application contexts and programmatic `registerBean` calls;
- `META-INF/spring.factories`, `AutoConfiguration.imports`, and `spring.components`;
- nested application/configuration classes discovered by a broader scan.

Check `exclude`, `excludeFilters`, custom ignore annotations, `@Profile`, `@Conditional*`, property/classpath conditions, missing dependencies, duplicate Bean names, override policy, and component indexes.

### Wildcard Semantics

Do not interpret component scan strings as simple Java package-prefix comparisons. `ClassPathScanningCandidateComponentProvider` converts a base package to a resource path and appends its resource pattern, normally `**/*.class`.

For example, a framework version may resolve:

```text
com.hotent.*
→ classpath*:com/hotent/*/**/*.class
```

The `*` can match `portal`, while the appended `**` continues through `special/actuator/...`. Verify this with the target's actual Spring libraries and classpath. Use `javap -v` to confirm annotations when decompiler output or scanner results disagree.

## Effective Route

Compose the route from:

```text
gateway/public prefix
→ proxy rewrite or strip-prefix rule
→ server.servlet.context-path / servlet path
→ class-level mapping
→ method-level mapping
→ HTTP method and content constraints
```

Account for multiple applications or ports in a combined deployment. A 200 SPA fallback, gateway-generated 404, or response from another Pod is not evidence that the target Controller handled the request.

When runtime access exists, prefer `RequestMappingHandlerMapping`, startup mapping logs, Bean names/source resources, deployed hashes, and container command lines.

## Servlet Security Decision Path

Review both legacy and modern configurations:

- `WebSecurityConfigurerAdapter` and `configure(WebSecurity/HttpSecurity)`;
- one or more `SecurityFilterChain` Beans;
- `securityMatcher`, request matchers, and `@Order`;
- custom Filters and their position relative to authentication and authorization;
- error/async dispatch and CORS preflight handling;
- MVC Interceptors, which do not replace servlet security filters.

Distinguish:

- `web.ignoring()`: bypasses the Spring Security filter chain;
- `permitAll()`: remains in the chain but authorization permits it;
- anonymous authentication: may satisfy poorly written “authentication object exists” checks.

## Method and Dynamic Authorization

Confirm method annotations are enabled by `@EnableMethodSecurity` or `@EnableGlobalMethodSecurity`. Check proxy limitations, self-invocation, final/private methods, and interface-vs-implementation annotations.

For database-driven URL-role mappings, determine behavior when the table is empty, a URL is missing or normalized differently, wildcard patterns overlap, loading fails, the cache is stale, or a super/admin shortcut applies. Missing mappings are secure only when the final decision is deny-by-default.

## JWT and Service Trust

Verify fixed accepted algorithms, adequate key material, `iss`, `aud`, `exp`, `nbf`, token type, revocation/rotation, refresh constraints, public signing/token-exchange endpoints, proxy/service headers, and `X-Forwarded-For` trust.

## Tenant and Object Authorization

Trace tenant context creation, propagation, clearing, and bypass helpers. Flag routes that disable tenant filtering and then query caller-controlled IDs without explicit ownership checks. Enforce authorization separately for files, workflows, tasks, departments, roles, accounts, and configuration.

## Effective Configuration

Resolve packaged defaults, external config, active profiles, environment/system properties, command-line options, configuration centers, ConfigMaps/Secrets, gateway/ingress rules, and management server exposure.

Record a value as a packaged default when production overrides are unavailable. A custom Controller under `/actuator` is not disabled merely because native Actuator exposure or management-port settings disable framework endpoints.
