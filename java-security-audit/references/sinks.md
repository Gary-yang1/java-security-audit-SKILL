# Java Security Sources and Sinks

Use this reference for candidate discovery. A match is an investigation lead, not a vulnerability or severity decision.

## Contents

- Common untrusted sources
- RCE, command, script, and expression execution
- Unsafe deserialization
- SQL, NoSQL, LDAP, and XPath injection
- SSRF and outbound connections
- Files, uploads, downloads, and archives
- XML and XXE
- Authentication, tokens, authorization, and tenancy
- Identity lifecycle, identifiers, external binding, and account creation
- Cryptography, TLS, and secrets
- Framework and business-risk surfaces

## Common Untrusted Sources

- HTTP: `@RequestParam`, `@RequestBody`, `@PathVariable`, headers, cookies, multipart parts, raw servlet input, GraphQL variables, WebSocket messages.
- Non-HTTP: JMS/Kafka/Rabbit messages, scheduled-job parameters, workflow variables, imported files, email content, cache entries, database fields, configuration centers, RPC/Feign parameters.
- Identity: JWT claims, SSO assertions, API keys, proxy headers, tenant IDs, account IDs, role aliases.
- Second-order inputs: values stored by one endpoint and interpreted later as SQL, URL, template, script, class name, file path, or expression.

## RCE, Command, Script, and Expression Execution

```bash
rg -n -g '*.java' \
  'Runtime\.getRuntime\(\)|new\s+ProcessBuilder|\.exec\(|GroovyShell|GroovyScriptEngine|ScriptEngineManager|SpelExpressionParser|Ognl|MVEL|Jexl|Nashorn|Graal|URLClassLoader|Method\.invoke|Class\.forName|InitialContext|\.lookup\(' .
```

Confirm:

- the attacker controls command arguments, script/template/expression text, class name, method, JNDI name, or dangerous object properties;
- fixed argument arrays are distinguished from shell strings;
- sandbox, AST restrictions, classloader boundaries, process isolation, and timeouts are actually effective;
- the execution component and route/job/consumer are registered.

Do not label `Runtime.exec`, reflection, or `Class.forName` as RCE without a controllable path and trigger.

## Unsafe Deserialization

```bash
rg -n -g '*.java' \
  'ObjectInputStream|readObject\(|readUnshared\(|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping|DefaultTyping|ParserConfig|SupportAutoType|JSON\.parse(Object|Array)?|new\s+Yaml\(|Constructor\(|readClassAndObject|HessianInput|ObjectMessage' .
```

Cover native Java serialization, Fastjson AutoType, Jackson polymorphic/default typing, SnakeYAML unsafe constructors, XStream, XMLDecoder, Hessian, Kryo, and JMS `ObjectMessage`.

Confirm untrusted bytes/text, active type resolution, affected version/configuration, a usable class/gadget path, and the point at which side effects occur. `JSON.parseObject` alone is not an RCE.

## SQL, NoSQL, LDAP, and XPath Injection

```bash
rg -n -F -g '*.xml' '${' .
rg -n -g '*.java' \
  'JdbcTemplate|NamedParameterJdbcTemplate|createNativeQuery|createQuery|prepareStatement|Statement|queryFor(Map|List)|\.execute\(|\.last\(|\.apply\(|String\.format\(|SELECT\s|UPDATE\s|DELETE\s|INSERT\s|LdapTemplate|DirContext|XPathExpression|XPathFactory' .
```

Confirm which fragments are user-controlled. Parameterize values; allowlist identifiers such as table names, columns, sort direction, operators, and stored procedure names. Treat keyword denylists and naive comment stripping as bypassable.

For MyBatis `${}`, distinguish fixed server constants or enumerated identifiers from request-controlled substitution. Review annotation mappers and dynamic SQL providers in addition to XML.

## SSRF and Outbound Connections

```bash
rg -n -g '*.java' \
  'new\s+URL\(|new\s+URI\(|openConnection\(|RestTemplate|WebClient|FeignClient|HttpClient|HttpClients|OkHttpClient|Jsoup\.connect|DriverManager\.getConnection|DataSource|socketFactory|setInstanceFollowRedirects|HostnameVerifier|TrustManager' .
```

Confirm control of scheme, authority, host, port, path, proxy, JDBC properties, or redirect target. Verify all of:

- scheme allowlist;
- DNS resolution and every A/AAAA result;
- loopback, RFC1918, link-local, multicast, IPv4-mapped IPv6, and cloud metadata blocking;
- alternative IP notations and DNS rebinding;
- redirect revalidation at every hop;
- outbound proxy/ACL enforcement;
- response limits, timeouts, and credential forwarding.

Opening a connection is enough for blind SSRF even if the response body is later rejected.

## Files, Uploads, Downloads, and Archives

```bash
rg -n -g '*.java' \
  'MultipartFile|transferTo\(|getOriginalFilename\(|new\s+File\(|Paths\.get\(|Path\.of\(|File(Input|Output)Stream|Files\.(read|write|copy|move)|ZipFile|ZipInputStream|extractAll|ArchiveInputStream|TarArchive|Content-Disposition|downloadFile' .
```

Check:

- canonical root enforcement after decoding and normalization;
- absolute paths, `..`, mixed separators, Unicode normalization, symlinks, hard links, and race conditions;
- archive entry paths, symlinks, entry count, compression ratio, per-file and total extracted size;
- upload authentication, extension, MIME, magic bytes, generated filename, storage location, executable/static serving, and active-content headers;
- download ownership, tenant, workflow/object ACL, guessability, share-token scope, and expiry.

An upload without an extension allowlist is not automatically Critical. Prove that stored content can execute, overwrite a sensitive file, or create a material active-content impact.

## XML and XXE

```bash
rg -n -g '*.java' \
  'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXBuilder|SAXReader|Unmarshaller|JAXBContext|parse\(' .
```

Check external general/parameter entities, DTD loading, XInclude, schema imports, transformer URI resolution, and library-version defaults. Confirm the parsed document is attacker-controlled and hardening is applied to the actual factory instance.

## Authentication, Tokens, Authorization, and Tenancy

```bash
rg -n -g '*.java' \
  'SecurityFilterChain|WebSecurityConfigurerAdapter|web\.ignoring|permitAll|anonymous|requestMatchers|antMatchers|securityMatcher|addPathPatterns|excludePathPatterns|PreAuthorize|Secured|RolesAllowed|EnableMethodSecurity|EnableGlobalMethodSecurity|Jwt|Jwts|Authorization|tenant|MultiTenant|setThreadLocalIgnore' .
```

Review token algorithms, key strength, issuer/audience/expiry, replay, refresh, revocation, and `kid`; public token-minting and password-reset flows; object ownership, IDOR, mass assignment, tenant-filter bypass; fail-open role tables; and spoofable gateway/service identity headers.

## Identity Lifecycle, Identifiers, External Binding, and Account Creation

Read [identity-lifecycle.md](identity-lifecycle.md) and inventory discovery, enrollment, verification, binding, approval, activation, recovery, session bootstrap, user or administrator creation, import, synchronization, and deprovisioning.

Do not treat UUIDs and account IDs as secrets by default. Determine whether another route incorrectly treats possession as authentication or authorization. Reverse-trace every identifier, reset code, token, ticket, role, tenant, and workflow-state precondition.

Search business verbs in addition to security keywords:

    rg -n -g '*.java' -g '*.xml' 'match|bind|flow|callback|poll|authorize|exchange|issue|approve|activate|invite|provision|register|regist|import|sync|impersonat|insert.*user|insert.*account' .

For external identity flows, prove that provider-issued server-side evidence supplies matched attributes. Caller-submitted phone, email, employee number, subject, union ID, or external account ID is not proof of identity.

For account creation, distinguish pending registration records from active users, then trace approval, password creation, status, tenant, role or group assignment, notification, and login eligibility.

## Cryptography, TLS, and Secrets

```bash
rg -n -g '*.{java,yml,yaml,properties,xml}' \
  'password|passwd|secret|api.?key|access.?key|private.?key|client.?secret|jwt|AES/ECB|DES|RC4|MD5|SHA-?1|SHA-?256|SecureRandom|Math\.random|Random\(|TrustManager|HostnameVerifier|setHostnameVerifier|setSSLSocketFactory' .
```

Differentiate active credentials from placeholders, defaults, comments, tests, and expired values. Redact values in output. Check password hashing for unique salts and adaptive cost; check encryption for authenticated modes, random nonces, key separation, and managed rotation.

Empty TrustManager methods and permissive HostnameVerifier implementations can enable MITM when used by reachable clients.

## Framework and Business-Risk Surfaces

Inspect Actuator, Druid, H2 Console, Swagger/OpenAPI, debug/test controllers, script consoles, data-source tests, SQL validators, import/export, schedulers, message consumers, workflow transitions, approval bypass, password recovery, SSO callbacks, CORS/CSRF, open redirects, and sensitive error responses.

Internal IP literals alone are normally informational. Promote them only when combined with credentials, active SSRF targeting, trust decisions, or meaningful sensitive architecture exposure.
