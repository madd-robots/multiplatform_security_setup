#!/usr/bin/env bash
# ShellCheck the whole project, plus project-specific safety gates that
# ShellCheck cannot express.
set -Eeuo pipefail
HERE=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P -- "${HERE}/.." && pwd)
cd "$ROOT"

if ! command -v shellcheck >/dev/null 2>&1; then
    printf 'shellcheck is not installed. Install it with:\n  sudo apt-get install shellcheck\n' >&2
    exit 127
fi

mapfile -t files < <(printf '%s\n' \
    bin/secure-debian-bootstrap \
    lib/*.sh lib/platforms/*.sh \
    tests/*.sh tests/fixtures/*.sh \
    tools/*.sh)

printf 'shellcheck %s\n\n' "$(shellcheck --version | awk '/version:/{print $2}')"
rc=0
shellcheck --shell=bash --external-sources --severity=style "${files[@]}" || rc=$?

printf '\n--- project safety gates ---\n'
gate() {
    local desc=$1 pattern=$2
    local hits
    # Exclude comments and the gate definitions themselves.
    hits=$(grep -RnE "$pattern" bin lib 2>/dev/null | grep -v '^\S*:[0-9]*: *#' || true)
    if [[ -n $hits ]]; then
        printf 'GATE FAILED: %s\n%s\n' "$desc" "$hits"
        return 1
    fi
    printf 'gate ok: %s\n' "$desc"
    return 0
}
gate "no eval"                       '(^|[^[:alnum:]_])eval[[:space:]]' || rc=1
gate "no curl piped into a shell"    'curl[^|]*\|[[:space:]]*(ba)?sh' || rc=1
gate "no apt-key usage"              '^[^#]*[^[:alnum:]_-]apt-key[[:space:]]+(add|adv|del)' || rc=1
gate "no trusted=yes emitted"        'trusted=(yes|true)"?[[:space:]]*$' || rc=1
gate "no sudo sh -c"                 'sudo[[:space:]]+(sh|bash)[[:space:]]+-c' || rc=1
gate "no sudo -E"                    'sudo[[:space:]]+-E' || rc=1
gate "no unguarded rm -rf"           'rm[[:space:]]+-rf[[:space:]]+[^-]' || rc=1

exit "$rc"
