#!/usr/bin/env bash
# Template rendering: correct template chosen, no repository mixing, no trust
# bypass, suite preservation, and refusal on unverified templates.
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
sdb_resolve_cmd readlink stat find grep sort tr >/dev/null 2>&1
SDB_LOG_STARTED=0
printf '== repository generation ==\n'

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

setup_platform() {
    t_reset_detection
    SDB_SYS_ROOT=$1
    sdb_detect_platform >/dev/null 2>&1
    # shellcheck source=/dev/null
    [[ -r "${ROOT}/lib/platforms/${SDB_PLATFORM}.sh" ]] && . "${ROOT}/lib/platforms/${SDB_PLATFORM}.sh"
    sdb_parse_repositories >/dev/null 2>&1
}

render_for() {
    local out=$2
    local -a vars=() sels=()
    mapfile -t vars < <(sdb_platform_call render_vars 2>/dev/null)
    mapfile -t sels < <(sdb_platform_call select_template 2>/dev/null)
    local sel tmpl dest
    : >"$out"
    for sel in "${sels[@]:-}"; do
        [[ -n $sel ]] || continue
        IFS=$'\t' read -r tmpl dest <<<"$sel"
        _sdb_render "${ROOT}/templates/${SDB_PLATFORM}/${tmpl}" "${out}.part" "${vars[@]:-}" 2>/dev/null
        cat "${out}.part" >>"$out"
        printf '%s\n' "# -> $dest" >>"$out"
    done
}

# --- every shipped template declares provenance ---
for p in termux debian ubuntu kali parrot mx-linux; do
    conf=$(sdb_template_meta_get "$p" confidence 2>/dev/null || echo "")
    assert_ne "$conf" "" "template ${p} records its confidence"
    src=$(sdb_template_meta_get "$p" source 2>/dev/null || echo "")
    assert_ne "$src" "" "template ${p} records its source"
done

# --- no template can ever disable verification ---
all=$(cat "${ROOT}"/templates/*/*.sources "${ROOT}"/templates/*/*.list \
          "${ROOT}"/templates/*/sources.list* 2>/dev/null)
assert_not_contains "$all" "trusted=yes"  "no template contains trusted=yes"
assert_not_contains "$all" "Trusted: yes" "no template contains Trusted: yes"
assert_not_contains "$all" "AllowUnauthenticated" "no template allows unauthenticated packages"
assert_not_contains "$all" "apt-key" "no template uses apt-key"

# --- Kali: deb822 chosen for 2026.2, branch preserved, no Debian mixed in ---
setup_platform "${FIX}/kali-purple"
assert_eq "$SDB_PLATFORM" "kali" "kali platform module loads"
render_for kali "${WORK}/kali.out"
out=$(cat "${WORK}/kali.out")
# Prose comments in a template may legitimately mention other branches, so the
# "no substitution" assertions look at active (non-prose) lines only.
active=$(grep -v '^#[[:space:]]' "${WORK}/kali.out")
assert_contains "$out" "kali-last-snapshot" "kali branch is preserved, not forced to rolling"
assert_not_contains "$active" "kali-rolling" "kali-rolling is not silently substituted"
assert_contains "$out" "http.kali.org" "kali uses the official kali host"
assert_contains "$out" "kali-archive-keyring.gpg" "kali uses Signed-By with its own keyring"
assert_not_contains "$out" "deb.debian.org" "NO Debian repository is mixed into Kali"
assert_not_contains "$out" "ubuntu.com" "NO Ubuntu repository is mixed into Kali"
assert_contains "$out" "kali.sources" "kali 2026.2 gets the deb822 target"

# --- Ubuntu: codename and components preserved ---
setup_platform "${FIX}/ubuntu-lts"
render_for ubuntu "${WORK}/ubuntu.out"
out=$(cat "${WORK}/ubuntu.out")
assert_contains "$out" "noble" "ubuntu codename is preserved"
assert_contains "$out" "noble-security" "ubuntu security suite is present"
assert_contains "$out" "security.ubuntu.com" "ubuntu security host is present"
assert_not_contains "$out" "multiverse" "ubuntu components are preserved (fixture had main universe only)"
assert_not_contains "$out" "proposed" "ubuntu -proposed is never written"
assert_not_contains "$out" "deb.debian.org" "NO Debian repository is mixed into Ubuntu"

# --- Parrot: direct security host preserved, backports disabled ---
setup_platform "${FIX}/parrot"
render_for parrot "${WORK}/parrot.out"
out=$(cat "${WORK}/parrot.out")
assert_contains "$out" "deb.parrot.sh/direct/parrot" "parrot security keeps the direct host"
assert_contains "$out" "echo-security" "parrot security suite matches the detected suite"
assert_contains "$out" "#deb https://deb.parrot.sh/parrot echo-backports" "parrot backports are written disabled"
assert_not_contains "$out" "http.kali.org" "NO Kali repository is substituted into Parrot"
assert_not_contains "$out" "deb.debian.org" "NO Debian repository is substituted into Parrot"

# --- MX: Debian entries are legitimate here, mirror preserved ---
setup_platform "${FIX}/mx-linux"
render_for mx "${WORK}/mx.out"
out=$(cat "${WORK}/mx.out")
assert_contains "$out" "mirror.example.org" "MX preserves the mirror discovered on the system"
assert_contains "$out" "trixie" "MX uses the Debian base codename"
assert_contains "$out" "deb.debian.org" "MX legitimately includes Debian archives"
assert_not_contains "$out" "http.kali.org" "NO Kali repository is mixed into MX"

# --- MX and Debian are secondary-confidence: activation must refuse ---
SDB_ALLOW_SECONDARY_TEMPLATE=0
out=$( sdb_check_template_confidence "mx-linux" 2>&1 ); rc=$?
assert_ne "$rc" "0" "secondary template refuses activation by default"
assert_contains "$out" "allow-secondary-template" "refusal explains how to proceed"
out=$( sdb_check_template_confidence "debian" 2>&1 ); rc=$?
assert_ne "$rc" "0" "debian secondary template refuses activation by default"
SDB_ALLOW_SECONDARY_TEMPLATE=1
out=$( sdb_check_template_confidence "mx-linux" 2>&1 ); rc=$?
assert_eq "$rc" "0" "secondary template proceeds with the explicit flag"
SDB_ALLOW_SECONDARY_TEMPLATE=0
out=$( sdb_check_template_confidence "kali" 2>&1 ); rc=$?
assert_eq "$rc" "0" "primary template needs no extra flag"

# --- Termux: only Termux hosts, no Signed-By, no /etc/apt ---
t_reset_detection
export PREFIX="${FIX}/termux/data/data/com.termux/files/usr"
export TERMUX_VERSION="0.119"
SDB_SYS_ROOT="${FIX}/termux"
sdb_detect_platform >/dev/null 2>&1
# shellcheck source=/dev/null
. "${ROOT}/lib/platforms/termux.sh"
render_for termux "${WORK}/termux.out"
out=$(cat "${WORK}/termux.out")
active=$(grep -v '^#[[:space:]]' "${WORK}/termux.out")
assert_contains "$out" "packages.termux.dev" "termux uses the official termux host"
assert_not_contains "$active" "Signed-By" "termux template writes no Signed-By (upstream uses trusted.gpg.d)"
assert_not_contains "$out" "deb.debian.org" "NO Debian repository is written for Termux"
assert_contains "$out" "com.termux" "termux destination stays under PREFIX"
assert_not_contains "$out" "# -> /etc/apt" "termux never targets /etc/apt"
unset PREFIX TERMUX_VERSION

# --- generic-debian refuses to rebuild at all ---
setup_platform "${FIX}/unknown-derivative"
assert_eq "$SDB_PLATFORM" "generic-debian" "unknown derivative classifies as generic-debian"
out=$( sdb_platform_call select_template 2>&1 ); rc=$?
assert_ne "$rc" "0" "generic-debian refuses repository reconstruction"
assert_contains "$out" "no verified official repository definition" "refusal explains why"

# --- official-host allowlist rejects a foreign URI ---
SDB_PLATFORM="kali"
assert_true  "sdb_uri_is_official http://http.kali.org/kali" "kali host accepted for kali"
assert_false "sdb_uri_is_official http://deb.debian.org/debian" "debian host rejected for kali"
assert_false "sdb_uri_is_official http://evil.example.net/debian" "unknown host rejected"

t_summary
