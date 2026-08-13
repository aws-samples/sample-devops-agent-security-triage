#!/bin/bash
# Repository lint. Run this before pushing or opening a merge request.
#
# It exists because of a specific miss: every script shipped with
# PROFILE="${PROFILE:-demo}", where "demo" was a profile that existed only on the
# author's machine. Nothing in the repo was wrong on that machine, so nothing
# caught it until someone else deployed the lab and every script failed on
# credentials. These checks are for that class of bug, where local state escapes
# into code that other people run.
#
# Exit 0 means clean. Exit 1 lists what to fix.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
fails=0
note() { printf '  %-58s %s\n' "$1" "$2"; }
fail() { note "$1" "FAIL"; fails=$((fails + 1)); }
pass() { note "$1" "ok"; }

files() {
  find . -type f \( -name '*.sh' -o -name '*.md' -o -name '*.yaml' -o -name '*.txt' \) \
    -not -path './.git/*' -not -path './prompts/rendered/*'
}

echo "Repository lint"
echo

# 1. The original bug. No script may default a profile to a specific name. The
#    AWS CLI already resolves credentials; pinning a name assumes the reader has
#    that profile, and "default" is no safer since it breaks SSO and env creds.
hardcoded=$(grep -rnE 'PROFILE:-[A-Za-z0-9_-]+' scripts/ 2>/dev/null \
  | grep -v 'lint-repo.sh')
if [ -n "$hardcoded" ]; then
  fail "no script hard codes an AWS profile name"
  echo "$hardcoded" | sed 's/^/      /'
else
  pass "no script hard codes an AWS profile name"
fi

# 2. Real account IDs. Only the AWS documentation examples are allowed.
bad_accounts=$(files | xargs grep -ohE '\b[0-9]{12}\b' 2>/dev/null \
  | grep -vE '^(111122223333|123456789012)$' | sort -u)
if [ -n "$bad_accounts" ]; then
  fail "only documentation example account IDs appear"
  echo "$bad_accounts" | sed 's/^/      /'
else
  pass "only documentation example account IDs appear"
fi

# 3. Real access key IDs. Documentation examples end in EXAMPLE.
bad_keys=$(files | xargs grep -ohE 'AKIA[0-9A-Z]{16}' 2>/dev/null \
  | grep -v 'EXAMPLE$' | sort -u)
if [ -n "$bad_keys" ]; then
  fail "no real looking access key IDs"
  echo "$bad_keys" | sed 's/^/      /'
else
  pass "no real looking access key IDs"
fi

# 4. Routable IP addresses. RFC 5737 documentation ranges and RFC 1918 private
#    ranges are fine; anything else is probably somebody's real address.
bad_ips=$(files | xargs grep -ohE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null \
  | grep -vE '^(0\.0\.0\.0|127\.0\.0\.1|255\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  | grep -vE '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)' \
  | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
if [ -n "$bad_ips" ]; then
  fail "no routable IP addresses outside documentation ranges"
  echo "$bad_ips" | sed 's/^/      /'
else
  pass "no routable IP addresses outside documentation ranges"
fi

# 5. Absolute paths into somebody's home directory.
if files | xargs grep -lnE '(/Users/|/home/)[a-z]' >/dev/null 2>&1; then
  fail "no absolute paths into a home directory"
  files | xargs grep -nE '(/Users/|/home/)[a-z]' 2>/dev/null | sed 's/^/      /' | head -5
else
  pass "no absolute paths into a home directory"
fi

# 6. OWASP labels carry the year, and carry it exactly once. The 2021 and 2025
#    lists disagree on the numbers this lab uses, so a bare label is ambiguous.
#    Lines that discuss the 2021 list are exempt, they need the old labels.
stale=$(files | xargs grep -nE '\bA0[0-9]\b' 2>/dev/null | grep -v ':2025' | grep -v '2021')
repeated=$(files | xargs grep -nE ':2025(:2025)+' 2>/dev/null)
if [ -n "$stale" ] || [ -n "$repeated" ]; then
  fail "OWASP labels carry the 2025 year exactly once"
  [ -n "$stale" ] && echo "$stale" | sed 's/^/      missing year: /' | head -5
  [ -n "$repeated" ] && echo "$repeated" | sed 's/^/      repeated year: /' | head -5
else
  pass "OWASP labels carry the 2025 year exactly once"
fi

# 7. Every script must parse.
syntax_bad=0
for f in scripts/*.sh; do
  bash -n "$f" 2>/dev/null || { fail "bash syntax: $f"; syntax_bad=1; }
done
[ "$syntax_bad" = "0" ] && pass "every script parses"

# 8. Secrets must not be stack outputs. An output is readable by anyone with
#    cloudformation:DescribeStacks, so credentials belong in Secrets Manager.
if awk '/^Outputs:/,0' template.yaml | grep -qE 'SecretAccessKey|SecretString|Password'; then
  fail "no credential material in stack outputs"
  awk '/^Outputs:/,0' template.yaml | grep -nE 'SecretAccessKey|SecretString|Password' | sed 's/^/      /'
else
  pass "no credential material in stack outputs"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "clean"
  exit 0
fi
echo "$fails check(s) failed"
exit 1
