#!/usr/bin/env bash
# Plant secrets the way they would actually arrive and require the gate to go
# red. A gate that has only ever seen clean input is not evidence of anything;
# this is how it was found not to see a token in a role default at all.
#
# Works on a throwaway copy of the tracked files as they are in the working
# tree - not a clone of HEAD, which would test yesterday's gate against
# today's edits - so the working tree is never touched.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/repo"
(cd "$root" && git ls-files -z | tar --null -T - -cf -) | tar -C "$work/repo" -xf -
cd "$work/repo"
git init -q
git config user.email falsify@example.invalid
git config user.name falsify
git add -A
git commit -q -m "working tree as tracked"

failed=0
plant() {
    local name=$1 file=$2 line=$3
    git checkout -q -- .
    printf '%s\n' "$line" >> "$file"
    if ./tests/no-secrets.sh >/dev/null 2>&1; then
        echo "SURVIVED  $name: the gate stayed clean with $line in $file"
        failed=1
    else
        echo "caught    $name"
    fi
}

plant "yaml/cloudflare-in-role-default" roles/certs/defaults/main.yml \
    'certs_cf_token: "vK9xQ2mZ8pL4wR7tY1uI3oP5aS6dF0gH2jK4lM7n"'
# Spelled in two halves so this file does not itself trip the vendor pattern
plant "yaml/tailscale-in-role-default" roles/tailscale/defaults/main.yml \
    'tailscale_auth_key: tskey-'"auth-kF7xQ2mZ8pCNTRL-9wR7tY1uI3oP5aS6dF0gH2jK4lM7nB3vC"
plant "toml/panel-token-in-example" inventory.example/nodes/example.toml \
    'token = "0123456789abcdef0123456789abcdef"'
plant "yaml/password-in-vault-example" vault.example.yml \
    'smtp_password: hunter2hunter2hunter2'
plant "key/private-key-block" roles/common/defaults/main.yml \
    '# -----BEGIN OPENSSH '"PRIVATE KEY-----"

git checkout -q -- .
if ./tests/no-secrets.sh >/dev/null 2>&1; then
    echo "clean     the gate passes the tree as committed"
else
    echo "RED       the gate is red before anything was planted; falsification proves nothing"
    failed=1
fi

exit "$failed"
