#!/usr/bin/env bash
set -euo pipefail

target="."
output=""

if [[ $# -ge 1 ]]; then
  target="$1"
fi
if [[ $# -ge 2 ]]; then
  output="$2"
fi

if [[ ! -d "$target" ]]; then
  printf 'Target must be a source directory: %s\n' "$target" >&2
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  printf 'ripgrep (rg) is required\n' >&2
  exit 2
fi

if [[ -n "$output" ]]; then
  output_dir="$(dirname "$output")"
  if [[ ! -d "$output_dir" ]]; then
    printf 'Output directory does not exist: %s\n' "$output_dir" >&2
    exit 2
  fi
  exec >"$output"
fi

section() {
  printf '\n== %s ==\n' "$1"
}

run_rg() {
  rg -n --no-heading -g '*.java' -g '*.kt' -g '*.groovy' -g '*.xml' "$1" "$target" \
    | rg -v ':[0-9]+:[[:space:]]*(package|import)[[:space:]]' || true
}

section "Identity-related entry points"
run_rg '@(Request|Get|Post|Put|Delete|Patch)Mapping|@Path\(|@(Kafka|Rabbit|Jms)Listener|@Scheduled|GraphQL|WebSocket' \
  | rg -i 'login|logout|auth|token|ticket|session|sso|oauth|oidc|saml|cas|user|account|admin|register|regist|signup|invite|enroll|provision|approve|activate|reset|recover|forgot|bind|match|callback|poll|import|sync|impersonat' || true

section "Sensitive identifier and capability response candidates"
run_rg 'map\.put\(|setMapParam\(|addAttribute\(|setHeader\(|sendRedirect\(|ResponseEntity|setUuid\(|setUserId\(|setAccountId\(|setTenantId\(|setCompanyId\(' \
  | rg -i 'uuid|user.?id|account.?id|tenant.?id|company.?id|client.?id|subject|union.?id|open.?id|employee|ticket|token|code|session|redirect|role|group' || true

section "Identifier lookups from contact, account, or external identity"
run_rg 'phone|mobile|mail|email|idNum|idCard|employee|accountNumber|username|unionId|openId|subject|externalId|certificate' \
  | rg -i 'find|get|select|query|lookup|match|bind|where|return|put\(' || true

section "Enrollment, creation, approval, activation, and import sinks"
run_rg 'register|regist|sign.?up|invite|enroll|provision|approve|activate|create.*(user|account|admin)|add.*(user|account|admin)|insert.*(user|account)|import.*(user|account)|sync.*(user|account)|is_admin|account_status|user_status' || true

section "Credential, recovery, MFA, and session lifecycle"
run_rg 'changePassword|resetPassword|updatePassword|verifyPassword|checkPassword|PasswordEncoder|setCredential|reset|recover|forgot|otp|totp|mfa|verification.?code|captcha|session|cookie|access.?token|refresh.?token|authorization.?code|ticket|logout|revoke|expire' || true

section "External identity binding and callback flows"
run_rg 'bind|binding|auto.?match|match|merge|callback|poll|unionId|openId|externalSubject|provider.?id|oauth|oidc|saml|cas|ldap' \
  | rg -i '@(Request|Get|Post|Put|Delete|Patch)Mapping|public[[:space:]]|protected[[:space:]]|private[[:space:]]|Service|DAO|Mapper|insert|update|select|query|get.*By|return[[:space:]]|put\(' || true

section "Authentication exclusions, allowlists, and fail-open candidates"
run_rg 'permitAll|anonymous|web\.ignoring|excludePathPatterns|addPathPatterns|requestMatchers|antMatchers|uriSet|white.?list|skip|PassToken|CheckToken|preHandle|doFilter|return\s+true|catch\s*\(' || true

section "Session and trust-artifact producers and consumers"
run_rg 'setAttribute\(|getAttribute\(|RedisTemplate|redisTemplate\.|RedisClient|CacheKey|getCache|setCookie\(|addCookie\(|getCookie\(|Authorization|Bearer|encrypt\(|decrypt\(|sign\(|verify\(|set[A-Za-z]*(Token|Ticket|Session)\(|get[A-Za-z]*(Token|Ticket|Session)\(' || true

section "Cross-module trust definition files"
rg -l -g '*.java' -g '*.kt' -g '*.groovy' -g '*.xml' -g '*.yml' -g '*.yaml' -g '*.properties' \
  'CacheKey|cache.?key|cookie|ticket|token|session|issuer|audience|redis|database' "$target" | sort || true

section "Potential key and credential definition files; values suppressed"
rg -l -g '*.java' -g '*.kt' -g '*.groovy' -g '*.xml' -g '*.yml' -g '*.yaml' -g '*.properties' \
  'private.?key|secret.?key|signing.?key|encrypt.*key|AES_KEY|client.?secret|password|passwd' "$target" | sort || true

section "Review reminder"
printf '%s\n' \
  'Convert candidates into a route ledger and identity-lifecycle matrix.' \
  'A match is not a vulnerability. Prove registration, reachability, controls, preconditions, and impact.' \
  'Reverse-trace every identifier, token, ticket, tenant, role, or workflow state required by a candidate.' \
  'Review redirected output completely in chunks; do not rely on a truncated terminal view.'
