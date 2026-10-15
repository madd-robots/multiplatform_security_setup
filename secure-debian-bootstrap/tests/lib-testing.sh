#!/usr/bin/env bash
# Minimal test harness. No external dependencies: bats is optional and not
# required to run these tests (see docs/operator-guide.md).
# shellcheck shell=bash

# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused to it. This is the
# project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153
TESTS_RUN=0
TESTS_FAILED=0
CURRENT_TEST=""

t_start() { CURRENT_TEST=$1; TESTS_RUN=$((TESTS_RUN + 1)); }

t_ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
t_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  \033[31mFAIL\033[0m %s\n       %s\n' "$CURRENT_TEST" "$1"
}

assert_eq() {
    t_start "$3"
    if [[ $1 == "$2" ]]; then t_ok "$3"; else t_fail "expected '$2', got '$1'"; fi
}
assert_ne() {
    t_start "$3"
    if [[ $1 != "$2" ]]; then t_ok "$3"; else t_fail "expected something other than '$2'"; fi
}
assert_true() {
    t_start "$2"
    if eval "$1"; then t_ok "$2"; else t_fail "expected success: $1"; fi
}
assert_false() {
    t_start "$2"
    if eval "$1"; then t_fail "expected failure: $1"; else t_ok "$2"; fi
}
assert_contains() {
    t_start "$3"
    if [[ $1 == *"$2"* ]]; then t_ok "$3"; else t_fail "expected to contain '$2'"; fi
}
assert_not_contains() {
    t_start "$3"
    if [[ $1 != *"$2"* ]]; then t_ok "$3"; else t_fail "must NOT contain '$2'"; fi
}
assert_file_exists() {
    t_start "$2"
    if [[ -e $1 ]]; then t_ok "$2"; else t_fail "missing file: $1"; fi
}
assert_file_absent() {
    t_start "$2"
    if [[ -e $1 ]]; then t_fail "file must not exist: $1"; else t_ok "$2"; fi
}

t_summary() {
    printf '\n%s: %d test(s), %d failure(s)\n' "${0##*/}" "$TESTS_RUN" "$TESTS_FAILED"
    ((TESTS_FAILED == 0))
}

# Load the project libraries against a fixture root.
t_load_libs() {
    local root=${1:?}
    SDB_ROOT_DIR=$root
    local l
    for l in common logging detect-platform preflight inventory repository-audit \
             backup quarantine repository-rebuild repository-validate \
             package-trust baseline-hardening rollback reporting; do
        # shellcheck source=/dev/null
        . "${root}/lib/${l}.sh"
    done
}

# Reset detection globals between fixtures.
t_reset_detection() {
    SDB_PLATFORM=""; SDB_FAMILY=""; SDB_OS_ID=""; SDB_OS_ID_LIKE=""; SDB_OS_NAME=""
    SDB_OS_VERSION_ID=""; SDB_OS_CODENAME=""; SDB_OS_PRETTY=""; SDB_VARIANT=""
    SDB_INIT=""; SDB_IS_TERMUX=0; SDB_CONFIDENCE=0; SDB_DETECT_AMBIGUOUS=0
    SDB_EVIDENCE=(); SDB_DETECT_CANDIDATES=(); SDB_WRITE_ROOTS=(); SDB_KEYRING_DIRS=()
    SDB_REPO_ENTRIES=(); SDB_PREFIX=""; SDB_APT_ETC=""
    SDB_FINDINGS_HIGH=0; SDB_FINDINGS_MEDIUM=0; SDB_FINDINGS_LOW=0
    unset TERMUX_VERSION PREFIX ANDROID_ROOT ANDROID_DATA 2>/dev/null || true
}
