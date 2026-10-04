#!/usr/bin/env bash
# Path safety: traversal, symlink escape, forbidden paths, platform isolation.
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused to it. This is the
# project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153
set -uo pipefail
HERE=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P -- "${HERE}/.." && pwd)
# shellcheck source=tests/lib-testing.sh
. "${HERE}/lib-testing.sh"
t_load_libs "$ROOT"
FIX=${SDB_TEST_FIXTURES:-"${HERE}/.fixtures"}
[[ -d $FIX ]] || bash "${HERE}/fixtures/make-fixtures.sh" "$FIX" >/dev/null
sdb_resolve_cmd readlink stat find rm >/dev/null 2>&1
SDB_LOG_STARTED=0
printf '== path safety ==\n'

# --- normalisation ---
assert_eq "$(sdb_path_normalise /etc/apt/../shadow)" "/etc/shadow" "traversal is normalised lexically"
assert_eq "$(sdb_path_normalise /a/b/./c//d)" "/a/b/c/d" "redundant components are removed"

# --- containment ---
assert_true  "sdb_path_is_within /etc/apt/sources.list /etc/apt" "file inside root is within it"
assert_false "sdb_path_is_within /etc/shadow /etc/apt" "file outside root is not within it"
assert_false "sdb_path_is_within /etc/apt /" "containment in / is never accepted"
assert_false "sdb_path_is_within /etc/aptitude/x /etc/apt" "prefix-only match is not containment"

# --- forbidden ---
for p in / /etc /usr /var /home /root /boot /data /sdcard; do
    assert_true "sdb_path_is_forbidden $p" "protected path is refused: $p"
done
assert_false "sdb_path_is_forbidden /etc/apt/sources.list" "an ordinary config file is not forbidden"

# --- manifest paths (rollback attack surface) ---
assert_false "sdb_manifest_path_is_safe '/etc/shadow'"        "absolute manifest path rejected"
assert_false "sdb_manifest_path_is_safe '../../etc/shadow'"   "traversal manifest path rejected"
assert_false "sdb_manifest_path_is_safe 'etc/../../shadow'"   "embedded traversal rejected"
assert_false "sdb_manifest_path_is_safe ''"                   "empty manifest path rejected"
assert_false "sdb_manifest_path_is_safe '-rf'"                "option-like manifest path rejected"
assert_true  "sdb_manifest_path_is_safe 'etc/apt/sources.list'" "ordinary relative path accepted"

# --- symlink escape ---
link="${FIX}/hostile/etc/apt/trusted.gpg.d/escape.gpg"
assert_false "sdb_symlink_is_safe '$link' '${FIX}/hostile/etc/apt'" "symlink escaping the APT root is rejected"
assert_true  "sdb_symlink_is_safe '$link' '${FIX}/hostile'" "the same link is accepted within a wider root"

# --- write-root guard: platform isolation ---
# Termux must never write to /etc/apt.
SDB_PLATFORM="termux"
SDB_WRITE_ROOTS=("${FIX}/termux/data/data/com.termux/files/usr/etc/apt")
out=$( sdb_guard_write_root "/etc/apt/sources.list" 2>&1 ); rc=$?
assert_ne "$rc" "0" "termux write to /etc/apt is refused"
assert_contains "$out" "outside declared roots" "refusal names the reason"
assert_true "sdb_guard_write_root '${FIX}/termux/data/data/com.termux/files/usr/etc/apt/sources.list'" \
    "termux write inside PREFIX is allowed"

# Non-Termux must never write into a Termux PREFIX.
SDB_PLATFORM="debian"
SDB_WRITE_ROOTS=("${FIX}/debian-stable/etc/apt")
out=$( sdb_guard_write_root "/data/data/com.termux/files/usr/etc/apt/sources.list" 2>&1 ); rc=$?
assert_ne "$rc" "0" "debian write into a Termux PREFIX is refused"

# --- no write root declared at all: fail closed ---
SDB_WRITE_ROOTS=()
out=$( sdb_guard_write_root "/etc/apt/sources.list" 2>&1 ); rc=$?
assert_ne "$rc" "0" "writes are refused before detection declares roots"

# --- safe_remove ---
tmp=$(mktemp -d); mkdir -p "$tmp/inside"; : >"$tmp/inside/f"
assert_true  "sdb_safe_remove '$tmp/inside/f' '$tmp'" "removal inside the required root succeeds"
out=$( sdb_safe_remove "/etc/passwd" "$tmp" 2>&1 ); rc=$?
assert_ne "$rc" "0" "removal outside the required root is refused"
rm -rf -- "$tmp"

t_summary
