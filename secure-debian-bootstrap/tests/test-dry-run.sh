#!/usr/bin/env bash
# End-to-end launcher behaviour: dry-run changes nothing, audit changes nothing,
# ambiguity and EOL releases are refused, and repeated runs are idempotent.
#
# These tests invoke the real launcher, but always against a fixture root and a
# throwaway state directory, so the host is never touched.
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused to it. This is the
# project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153
set -uo pipefail
HERE=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P -- "${HERE}/.." && pwd)
# shellcheck source=tests/lib-testing.sh
. "${HERE}/lib-testing.sh"
FIX=${SDB_TEST_FIXTURES:-"${HERE}/.fixtures"}
[[ -d $FIX ]] || bash "${HERE}/fixtures/make-fixtures.sh" "$FIX" >/dev/null
BIN="${ROOT}/bin/secure-debian-bootstrap"
printf '== end to end ==\n'

WORK=$(mktemp -d); trap 'rm -rf -- "$WORK"' EXIT

# Snapshot a tree so we can prove nothing changed.
snapshot() { (cd "$1" && find . \( -type f -o -type l \) -printf '%p %s %m %l\n' 2>/dev/null | sort); }

run_sdb() {
    local sys=$1; shift
    "$BIN" --sys-root "$sys" --state-dir "${WORK}/state" --non-interactive "$@" 2>&1
}

# --- help and version work without touching anything ---
out=$("$BIN" --version 2>&1); rc=$?
assert_eq "$rc" "0" "--version exits 0"
assert_contains "$out" "secure-debian-bootstrap" "--version names the tool"
out=$("$BIN" --help 2>&1); rc=$?
assert_eq "$rc" "0" "--help exits 0"
assert_contains "$out" "default: --audit" "help states that the default mode changes nothing"

# --- unknown option is a usage error ---
out=$("$BIN" --definitely-not-an-option 2>&1); rc=$?
assert_eq "$rc" "2" "an unknown option exits with the usage code"

# --- audit changes nothing ---
SYS="${WORK}/audit-sys"; cp -a "${FIX}/debian-stable" "$SYS"
before=$(snapshot "$SYS")
out=$(run_sdb "$SYS" --audit); rc=$?
after=$(snapshot "$SYS")
assert_eq "$after" "$before" "audit mode leaves the system byte-identical"
assert_contains "$out" "detection" "audit reports detection"

# --- dry-run repair changes nothing and prints a plan ---
SYS2="${WORK}/dry-sys"; cp -a "${FIX}/kali-purple" "$SYS2"
before=$(snapshot "$SYS2")
out=$(run_sdb "$SYS2" --repair-repositories --dry-run --no-network); rc=$?
after=$(snapshot "$SYS2")
assert_eq "$after" "$before" "dry-run repair leaves the system byte-identical"
assert_contains "$out" "dry run" "dry-run announces itself"
assert_contains "$out" "0 applied" "dry-run applies nothing"

# --- ambiguous platform refuses every modifying mode, even with --yes ---
SYS3="${WORK}/amb-sys"; cp -a "${FIX}/ambiguous" "$SYS3"
before=$(snapshot "$SYS3")
out=$(run_sdb "$SYS3" --repair-repositories --yes --no-network); rc=$?
after=$(snapshot "$SYS3")
assert_eq "$rc" "3" "ambiguous detection exits with the detection code"
assert_eq "$after" "$before" "nothing is changed on an ambiguous system"
assert_contains "$out" "ambiguous" "the refusal explains the ambiguity"
assert_contains "$out" "cannot override" "the refusal states that --yes cannot override it"

# --- EOL release refuses repair ---
SYS4="${WORK}/eol-sys"; cp -a "${FIX}/eol-release" "$SYS4"
before=$(snapshot "$SYS4")
out=$(run_sdb "$SYS4" --repair-repositories --yes --no-network); rc=$?
after=$(snapshot "$SYS4")
assert_eq "$rc" "7" "an EOL release exits with the release code"
assert_eq "$after" "$before" "nothing is changed on an EOL release"
assert_contains "$out" "end of life" "the refusal explains the EOL condition"
assert_not_contains "$out" "old-releases.ubuntu.com" "archive repositories are not used silently"

# --- generic Debian derivative: audit works, repair refuses ---
SYS5="${WORK}/gen-sys"; cp -a "${FIX}/unknown-derivative" "$SYS5"
before=$(snapshot "$SYS5")
out=$(run_sdb "$SYS5" --audit); rc=$?
assert_eq "$rc" "0" "audit succeeds on an unknown derivative"
out=$(run_sdb "$SYS5" --repair-repositories --yes --no-network); rc=$?
after=$(snapshot "$SYS5")
assert_ne "$rc" "0" "repair is refused on an unknown derivative"
assert_eq "$after" "$before" "nothing is changed on an unknown derivative"

# --- hostile configuration: findings are raised, audit still changes nothing ---
SYS6="${WORK}/hostile-sys"; cp -a "${FIX}/hostile" "$SYS6"
before=$(snapshot "$SYS6")
out=$(run_sdb "$SYS6" --audit --strict); rc=$?
after=$(snapshot "$SYS6")
assert_eq "$after" "$before" "audit of a hostile system changes nothing"
assert_eq "$rc" "11" "--strict exits with the findings code when high findings exist"
assert_contains "$out" "apt_hook"                "the DPkg::Pre-Invoke hook is found"
assert_contains "$out" "repo_trusted_yes"        "trusted=yes is found"
assert_contains "$out" "apt_verification_disabled" "AllowUnauthenticated is found"
assert_contains "$out" "repo_duplicate"          "duplicate repositories are found"
assert_contains "$out" "repo_cross_distribution" "a Kali repository on Debian is found"
assert_contains "$out" "repo_development_suite"  "a sid entry on stable is found"
assert_contains "$out" "unsafe_symlink"          "the escaping symlink is found"
assert_contains "$out" "apt_pinning"             "pinning is found"
assert_contains "$out" "apt_conf_executable"     "an executable apt.conf.d file is found"

# --- proxy credentials are redacted everywhere ---
assert_not_contains "$out" "hunter2" "proxy credentials never appear in output"
logs=$(cat "${WORK}"/state/runs/*/run.log 2>/dev/null)
assert_not_contains "$logs" "hunter2" "proxy credentials never appear in the log file"
events=$(cat "${WORK}"/state/runs/*/events.jsonl 2>/dev/null)
assert_not_contains "$events" "hunter2" "proxy credentials never appear in the event log"

# --- backup-only is idempotent and never overwrites a backup ---
SYS7="${WORK}/backup-sys"; cp -a "${FIX}/debian-stable" "$SYS7"
run_sdb "$SYS7" --backup-only >/dev/null 2>&1
n1=$(find "${WORK}/state/backups" -maxdepth 1 -mindepth 1 -type d | wc -l)
run_sdb "$SYS7" --backup-only >/dev/null 2>&1
n2=$(find "${WORK}/state/backups" -maxdepth 1 -mindepth 1 -type d | wc -l)
assert_true "(( n2 > n1 ))" "each backup run creates a new backup, never overwriting the old one"

# --- Termux never writes to /etc/apt, even end to end ---
out=$( export PREFIX="${FIX}/termux/data/data/com.termux/files/usr" TERMUX_VERSION=0.119
       "$BIN" --sys-root "${FIX}/termux" --state-dir "${WORK}/tstate" --audit --non-interactive 2>&1 )
assert_contains "$out" "Is Termux:             yes" "the launcher detects Termux end to end"
assert_contains "$out" "com.termux" "the Termux APT root is under PREFIX"
tlog=$(cat "${WORK}"/tstate/runs/*/run.log 2>/dev/null)
assert_not_contains "$tlog" "write roots:           /etc/apt" "Termux never declares /etc/apt as a write root"

t_summary
