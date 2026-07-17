#!/usr/bin/env bash
set -euo pipefail

target="${1:-.}"

section() {
  printf '\n== %s ==\n' "$1"
}

if [[ ! -e "$target" ]]; then
  printf 'Target does not exist: %s\n' "$target" >&2
  exit 2
fi

section "Target"
printf '%s\n' "$target"

if [[ -f "$target" ]]; then
  case "$target" in
    *.jar|*.war)
      section "Artifact hash"
      if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$target"
      elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$target"
      else
        printf 'No SHA-256 utility found\n'
      fi

      section "Manifest"
      unzip -p "$target" META-INF/MANIFEST.MF 2>/dev/null || true

      section "Packaged application classes"
      jar tf "$target" | rg '^(BOOT-INF/classes|WEB-INF/classes)/.*\.class$' | sed -n '1,160p' || true

      section "Packaged dependencies"
      jar tf "$target" | rg '^(BOOT-INF/lib|WEB-INF/lib)/.*\.(jar|zip)$' | sort || true

      section "Configuration and registration resources"
      jar tf "$target" | rg '(application|bootstrap).*(yml|yaml|properties)$|spring\.factories$|AutoConfiguration\.imports$|spring\.components$|web\.xml$' | sort || true
      ;;
    *)
      printf 'Supported artifact extensions: .jar, .war\n' >&2
      exit 2
      ;;
  esac
  exit 0
fi

if ! command -v rg >/dev/null 2>&1; then
  printf 'ripgrep (rg) is required for directory inventory\n' >&2
  exit 2
fi

section "Code counts"
printf 'Java: '
{ rg --files "$target" -g '*.java' || true; } | wc -l | tr -d ' '
printf 'XML: '
{ rg --files "$target" -g '*.xml' || true; } | wc -l | tr -d ' '
printf 'YAML/properties: '
{ rg --files "$target" -g '*.yml' -g '*.yaml' -g '*.properties' || true; } | wc -l | tr -d ' '

section "Build and deployment files"
rg --files "$target" -g 'pom.xml' -g 'build.gradle*' -g 'settings.gradle*' -g 'gradle.lockfile' -g 'Dockerfile*' -g '*.yml' -g '*.yaml' | sed -n '1,200p' || true

section "Application and configuration classes"
rg -n -g '*.java' '@SpringBootApplication|@ComponentScan|@Import\(|SecurityFilterChain|WebSecurityConfigurerAdapter|@EnableMethodSecurity|@EnableGlobalMethodSecurity|implements\s+WebMvcConfigurer' "$target" | sed -n '1,240p' || true

section "HTTP and messaging entry points"
rg -n -g '*.java' '@(RestController|Controller)|@(Request|Get|Post|Put|Delete|Patch)Mapping|@KafkaListener|@RabbitListener|@JmsListener|@Scheduled' "$target" | sed -n '1,300p' || true

section "High-priority sink candidates"
rg -n -g '*.java' 'Runtime\.getRuntime\(\)|ProcessBuilder|GroovyShell|GroovyScriptEngine|ScriptEngineManager|ObjectInputStream|readObject\(|activateDefaultTyping|enableDefaultTyping|InitialContext|\.lookup\(|SpelExpressionParser|DriverManager\.getConnection|openConnection\(|transferTo\(|extractAll|JdbcTemplate|createNativeQuery' "$target" | sed -n '1,300p' || true

section "Security exclusions and bypass helpers"
rg -n -g '*.java' 'web\.ignoring|permitAll|anonymous|excludePathPatterns|setThreadLocalIgnore|MultiTenant|TrustManager|HostnameVerifier' "$target" | sed -n '1,240p' || true
