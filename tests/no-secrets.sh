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

# A real value assigned to a secret-shaped key. The example file assigns the
# literal replace-me, which is the point: it must stay a placeholder
if git grep -nIE '^[[:space:]]*(token|password|secret|authkey|auth_key|cf_token)[[:space:]]*=[[:space:]]*"[^"]{8,}"' \
    -- "${tracked[@]}" | grep -vE '(replace-me|example|CHANGEME|\{\{)' >&2; then
    report "literal secret assignment"
fi

# Node files are the private registry; none of them belong in git at all
if git ls-files | grep -qE '^inventory/nodes/'; then
    report "a node file is tracked; that directory is the private registry"
fi

[[ $fail -eq 0 ]] && echo "secret-gate: clean"
exit "$fail"
