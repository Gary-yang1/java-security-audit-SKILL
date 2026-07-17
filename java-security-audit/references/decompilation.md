# JAR, WAR, and Decompiled-Code Verification

Use this reference when source is missing, incomplete, generated, or does not obviously match the deployed artifact.

## Establish Artifact Identity

Record filename, byte size, timestamp, SHA-256, manifest, start class, Java version, and Spring Boot loader version. Compare the hash with the deployed Pod/container artifact when possible.

For Spring Boot JARs inspect:

```bash
unzip -p app.jar META-INF/MANIFEST.MF
jar tf app.jar | rg '^BOOT-INF/(classes|lib)/'
```

For WARs inspect `WEB-INF/classes`, `WEB-INF/lib`, `web.xml`, servlet initializers, and container configuration. Treat final packaged libraries as stronger dependency evidence than unresolved POM declarations.

## Decompile Deliberately

- Extract or decompile relevant modules first; preserve archive paths in evidence.
- Use CFR or Fernflower, but confirm critical annotations and bytecode with `javap -v` or `javap -c -p`.
- Expect synthetic casts, inaccurate generics, altered try/catch structure, missing parameter names, and non-original line numbers.
- Inspect Kotlin/Scala metadata and multi-release JAR entries when applicable.
- Do not treat a decompiler failure or omitted annotation as proof that code is absent.

```bash
javap -classpath module.jar -v com.example.Target
javap -classpath module.jar -c -p com.example.Target
```

## Verify Registration and Resources

Inspect `spring.factories`, `AutoConfiguration.imports`, `spring.components`, XML contexts, mapper files, templates, packaged YAML/properties, main classes, and `@Import` paths.

Use the target's actual Spring libraries when testing candidate-component or path-matching behavior. A test against another framework version is supporting evidence only.

## Resolve Source-to-Binary Drift

If source and runtime behavior disagree:

1. compare hashes and build timestamps;
2. check the Pod, port, context path, and gateway rewrite;
3. compare packaged and external configuration;
4. inspect runtime Bean/mapping lists;
5. check shaded/duplicate classes and classpath order;
6. record the disagreement and lower deployment confidence until resolved.

Do not force contradictory evidence into a definitive source-only or HTTP-status-only conclusion.

## Dependency Findings

Retain evidence for exact packaged version, authoritative affected range, reachable vulnerable API, configuration/environmental preconditions, exposed protocol/port, remediation version, and upgrade compatibility.

Keep unreachable version matches in an appendix or dependency inventory rather than counting them as confirmed application vulnerabilities.
