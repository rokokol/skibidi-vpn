#!/usr/bin/env bash
# Refuse to ship a secret that slipped past .gitignore.
#
# .gitignore keeps a file out; this keeps a value out of a file that belongs
# here. Both are needed: the leak that matters is a token pasted into a role
# default, not a stray file.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
report() {
    printf 'secret-gate: %s\n' "$1" >&2
    fail=1
}

# Tracked files only — an untracked scratch file is not about to be pushed
mapfile -t tracked < <(git ls-files)
[[ ${#tracked[@]} -gt 0 ]] || {
    echo "secret-gate: nothing tracked yet" >&2
    exit 0
}

if git grep -nIE 'BEGIN (OPENSSH|RSA|EC|PGP) PRIVATE KEY' -- "${tracked[@]}" >&2; then
    report "private key material"
fi

if git grep -nIE '(github_pat_|ghp_)[A-Za-z0-9_]{20,}' -- "${tracked[@]}" >&2; then
    report "GitHub token"
fi

# A real value assigned to a secret-shaped key, in either of the two syntaxes
# tracked files use: TOML's `key = "value"` and YAML's `key: value`. The key
# matches by shape rather than by an exact name, because the value that matters
# is a token pasted into a role default, and role defaults carry a prefix
# (certs_cf_token, tailscale_auth_key). The example files assign the literal
# replace-me, which is the point: it must stay a placeholder
# The exclusions look only at the matched line, after the `file:line:` prefix
# git grep adds - a filter that also saw the path once waved through every
# file under roles/ and everything named example
if git grep -nIE '^[[:space:]]*[A-Za-z0-9_.-]*(token|password|secret|auth_?key|api_?key|private_?key)[A-Za-z0-9_-]*[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]#]{8,}' \
    -- "${tracked[@]}" \
    | grep -vE '^[^:]+:[0-9]+:([[:space:]]*#|.*(replace-me|CHANGEME|\{\{|lookup\()|[^:=]*[:=][[:space:]]*["'"'"']?(/|[A-Za-z0-9_.-]*\.(pem|key|crt|json|yml|toml|otf|py|sh)["'"'"']?([[:space:]]|$)))' >&2; then
    report "literal secret assignment"
fi

# Tokens whose issuer stamps a recognisable prefix on them, wherever they sit
if git grep -nIE '(tskey-(auth|api|client)-[A-Za-z0-9]{6,}|sk-[A-Za-z0-9]{20,}|xox[bpa]-[0-9A-Za-z-]{10,})' -- "${tracked[@]}" >&2; then
    report "vendor-prefixed token"
fi

# Node files are the private registry; none of them belong in git at all
if git ls-files | grep -qE '^inventory/nodes/'; then
    report "a node file is tracked; that directory is the private registry"
fi

[[ $fail -eq 0 ]] && echo "secret-gate: clean"
exit "$fail"
