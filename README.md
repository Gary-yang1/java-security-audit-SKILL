# Java Security Audit Skill

Evidence-driven Java security auditing for Codex. This repository contains a reusable skill for reviewing Java Web, Spring Boot, SSM, microservice, JAR, WAR, and decompiled applications.

The workflow distinguishes dangerous code from exploitable behavior by requiring a complete chain across attacker input, transformations, component registration, route reachability, authorization, effective configuration, the dangerous sink, and concrete impact.

## Included Skill

### `java-security-audit`

The skill covers:

- authentication bypass, authorization failures, IDOR, and tenant isolation;
- command, script, expression, and deserialization RCE;
- SQL/NoSQL/LDAP/XPath injection;
- HTTP/JDBC SSRF and redirect/DNS bypasses;
- upload, download, path traversal, Zip Slip, and archive risks;
- XML/XXE, JWT, cryptography, TLS, and exposed secrets;
- Spring component scanning, route registration, filter chains, and method security;
- JAR/WAR inventory, bytecode verification, dependency reachability, and source-to-binary drift;
- confidence classification, CVSS preconditions, safe validation, and report acceptance criteria.

## Install

Ask Codex to install the skill from:

```text
https://github.com/Gary-yang1/java-security-audit-SKILL/tree/main/java-security-audit
```

Or use the bundled skill installer:

```bash
python3 ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo Gary-yang1/java-security-audit-SKILL \
  --path java-security-audit
```

The skill is installed to `~/.codex/skills/java-security-audit` and becomes available on the next Codex turn.

## Use

Invoke it explicitly:

```text
Use $java-security-audit to audit this Java application and report only evidence-backed high and critical findings.
```

It can also trigger automatically for Java source-code audits, packaged JAR/WAR review, decompiled-code analysis, and Java security-report preparation.

## Repository Layout

```text
java-security-audit/
├── SKILL.md
├── agents/
│   └── openai.yaml
├── references/
│   ├── decompilation.md
│   ├── sinks.md
│   └── spring-security.md
└── scripts/
    └── inventory.sh
```

`scripts/inventory.sh` performs a read-only first-pass inventory. It supports Java source directories and executable `.jar`/`.war` artifacts.

```bash
java-security-audit/scripts/inventory.sh /path/to/source
java-security-audit/scripts/inventory.sh /path/to/application.jar
```

## Local Requirements

- Codex with skill support;
- `rg` for source discovery;
- Bash for the inventory script;
- JDK tools such as `jar` and `javap` for packaged-artifact analysis;
- `unzip` and a SHA-256 utility for artifact inventory.

Dynamic validation is not automatic. Only perform it within explicit authorization, and prefer harmless runtime evidence over destructive or weaponized payloads.
