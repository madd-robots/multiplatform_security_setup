#!/usr/bin/env bash
# Platform detection: correct classification, refusal on ambiguity, no
# misclassification of Termux or of unknown derivatives.
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

SDB_DEBUG=0; SDB_VERBOSE=0; SDB_LOG_STARTED=0
printf '== detection ==\n'

detect_in() {
    t_reset_detection
    SDB_SYS_ROOT=$1
    sdb_detect_platform >/dev/null 2>&1
}

detect_in "${FIX}/debian-stable"
assert_eq "$SDB_PLATFORM" "debian" "debian-stable is detected as debian"
assert_eq "$SDB_OS_CODENAME" "trixie" "debian codename is trixie"
assert_eq "$SDB_IS_TERMUX" "0" "debian is not Termux"
assert_true "(( SDB_CONFIDENCE >= 70 ))" "debian confidence is sufficient"

detect_in "${FIX}/ubuntu-lts"
assert_eq "$SDB_PLATFORM" "ubuntu" "ubuntu-lts is detected as ubuntu"
assert_eq "$SDB_OS_CODENAME" "noble" "ubuntu codename is noble"

detect_in "${FIX}/kali-purple"
assert_eq "$SDB_PLATFORM" "kali" "kali-purple is detected as kali (not a separate platform)"
assert_eq "$SDB_VARIANT" "purple" "kali purple variant is recorded"

detect_in "${FIX}/parrot"
assert_eq "$SDB_PLATFORM" "parrot" "parrot is detected as parrot"

detect_in "${FIX}/mx-linux"
assert_eq "$SDB_PLATFORM" "mx-linux" "mx is detected as mx-linux, not debian"
assert_eq "$SDB_INIT" "sysvinit" "mx sysvinit is detected, not assumed systemd"

detect_in "${FIX}/unknown-derivative"
assert_eq "$SDB_PLATFORM" "generic-debian" "unknown derivative is generic-debian, not debian"
assert_ne "$SDB_PLATFORM" "debian" "apt existing does not make a system Debian"

detect_in "${FIX}/ambiguous"
assert_eq "$SDB_DETECT_AMBIGUOUS" "1" "conflicting derivatives are flagged ambiguous"
assert_eq "$SDB_CONFIDENCE" "0" "ambiguous detection has zero confidence"

# Termux: driven by environment plus filesystem evidence.
t_reset_detection
export PREFIX="${FIX}/termux/data/data/com.termux/files/usr"
export TERMUX_VERSION="0.119"
SDB_SYS_ROOT="${FIX}/termux"
sdb_detect_platform >/dev/null 2>&1
assert_eq "$SDB_PLATFORM" "termux" "termux is detected as termux"
assert_eq "$SDB_IS_TERMUX" "1" "termux flag is set"
assert_eq "$SDB_INIT" "android" "termux init is android, never systemd"
assert_contains "$SDB_APT_ETC" "com.termux" "termux APT root is under PREFIX"
assert_not_contains "$SDB_APT_ETC" "^/etc/apt" "termux APT root is not /etc/apt"
unset PREFIX TERMUX_VERSION

t_summary
