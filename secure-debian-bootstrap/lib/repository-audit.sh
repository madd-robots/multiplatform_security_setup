#!/usr/bin/env bash
# repository-audit.sh - findings over untrusted APT configuration.
#
# Every file read here is treated as hostile input (threat model T1). Files are
# parsed line-wise with `read -r`; nothing is sourced, eval'd, globbed into a
# command, or executed.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_REPO_AUDIT:-} ]] && return 0
SDB_LIB_REPO_AUDIT=1

SDB_RELEASE_STATUS="unknown"   # supported|eol|prerelease|rolling|unknown
SDB_RELEASE_EOL_DATE=""
declare -ga SDB_REPO_ENTRIES=()   # "file<TAB>lineno<TAB>type<TAB>uri<TAB>suite<TAB>components<TAB>options"

# ---------------------------------------------------------------------------
# Repository definition parsing
# ---------------------------------------------------------------------------

# _sdb_parse_list_file <file> - legacy one-line format
_sdb_parse_list_file() {
    local file=${1:?} lineno=0 line opts="" type uri suite comps
    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$((lineno + 1))
        line=$(sdb_trim "$line")
        [[ -z $line || $line == '#'* ]] && continue
        [[ $line == deb* ]] || continue
        opts=""
        # Extract a bracketed option group if present: deb [opt=val ...] uri ...
        if [[ $line == *'['*']'* ]]; then
            opts=${line#*[}
            opts=${opts%%]*}
            line="${line%%[*}${line#*]}"
            line=$(sdb_trim "$line")
        fi
        # shellcheck disable=SC2086
        set -- $line
        type=${1:-}; uri=${2:-}; suite=${3:-}; shift 3 2>/dev/null || true
        comps="$*"
        SDB_REPO_ENTRIES+=("${file}"$'\t'"${lineno}"$'\t'"${type}"$'\t'"${uri}"$'\t'"${suite}"$'\t'"${comps}"$'\t'"${opts}")
    done <"$file"
}

# _sdb_parse_sources_file <file> - deb822 format
_sdb_parse_sources_file() {
    local file=${1:?} lineno=0 startline=1 line key value
    local types="" uris="" suites="" comps="" signed="" trusted="" enabled="yes"
    _flush() {
        [[ -n $uris$suites ]] || return 0
        local uri suite opts=""
        [[ -n $signed ]] && opts="signed-by=${signed}"
        [[ -n $trusted ]] && opts="${opts:+${opts},}trusted=${trusted}"
        [[ $enabled == "no" ]] && opts="${opts:+${opts},}enabled=no"
        for uri in $uris; do
            for suite in $suites; do
                SDB_REPO_ENTRIES+=("${file}"$'\t'"${startline}"$'\t'"${types:-deb}"$'\t'"${uri}"$'\t'"${suite}"$'\t'"${comps}"$'\t'"${opts}")
            done
        done
        types=""; uris=""; suites=""; comps=""; signed=""; trusted=""; enabled="yes"
    }
    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$((lineno + 1))
        if [[ -z $(sdb_trim "$line") ]]; then
            _flush
            startline=$((lineno + 1))
            continue
        fi
        [[ $(sdb_trim "$line") == '#'* ]] && continue
        [[ $line == *:* ]] || continue
        key=$(sdb_trim "${line%%:*}")
        value=$(sdb_trim "${line#*:}")
        case ${key,,} in
            types)      types=$value ;;
            uris)       uris=$value ;;
            suites)     suites=$value ;;
            components) comps=$value ;;
            signed-by)  signed=$value ;;
            trusted)    trusted=$value ;;
            enabled)    [[ ${value,,} == "no" || ${value,,} == "false" ]] && enabled="no" ;;
        esac
    done <"$file"
    _flush
    unset -f _flush
}

# sdb_parse_repositories: fill SDB_REPO_ENTRIES from the live configuration.
sdb_parse_repositories() {
    local etc=${SDB_APT_ETC:?} f
    SDB_REPO_ENTRIES=()
    [[ -f "${etc}/sources.list" && ! -L "${etc}/sources.list" ]] && \
        _sdb_parse_list_file "${etc}/sources.list"
    if [[ -d "${etc}/sources.list.d" ]]; then
        while IFS= read -r -d '' f; do
            case $f in
                *.list)    _sdb_parse_list_file "$f" ;;
                *.sources) _sdb_parse_sources_file "$f" ;;
            esac
        done < <(sdb_cmd find "${etc}/sources.list.d" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    sdb_log_verbose "parsed ${#SDB_REPO_ENTRIES[@]} repository entries"
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

# sdb_audit_trust_bypass: entries that weaken or disable verification.
sdb_audit_trust_bypass() {
    local entry file lineno _type uri suite comps opts
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno type uri suite comps opts <<<"$entry"
        case ${opts,,} in
            *trusted=yes*|*trusted=true*)
                sdb_log_finding high "repo_trusted_yes" "${file}:${lineno}" \
                    "signature verification is disabled for ${uri} ${suite}" ;;
        esac
        case ${uri,,} in
            http://*)
                # Plain HTTP is not itself a vulnerability for a signed archive,
                # but it is worth recording, and it is a real problem when
                # combined with trusted=yes.
                sdb_log_finding low "repo_plain_http" "${file}:${lineno}" "${uri}" ;;
            file:*|copy:*|cdrom:*)
                sdb_log_finding medium "repo_local_transport" "${file}:${lineno}" "${uri}" ;;
        esac
        if [[ -z $uri || -z $suite ]]; then
            sdb_log_finding medium "repo_malformed" "${file}:${lineno}" "incomplete entry: ${entry//$'\t'/ }"
        fi
    done
    return 0
}

# sdb_audit_duplicates: the same uri+suite+component defined more than once.
sdb_audit_duplicates() {
    local entry file lineno _type uri suite comps opts key
    declare -A seen=()
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno type uri suite comps opts <<<"$entry"
        key="${type}|${uri%/}|${suite}"
        if [[ -n ${seen[$key]:-} ]]; then
            sdb_log_finding medium "repo_duplicate" "${file}:${lineno}" \
                "duplicates ${seen[$key]} (${uri} ${suite})"
        else
            seen[$key]="${file}:${lineno}"
        fi
    done
    return 0
}

# sdb_audit_foreign: repository hosts belonging to another distribution.
# The platform module decides what "foreign" means here - MX legitimately uses
# Debian archives, Kali legitimately does not.
sdb_audit_foreign() {
    local entry file lineno _type uri suite comps opts host pattern
    local -a foreign=()
    local fn
    fn=$(sdb_platform_fn foreign_origins)
    if declare -F "$fn" >/dev/null 2>&1; then
        mapfile -t foreign < <("$fn")
    fi
    ((${#foreign[@]})) || return 0
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno type uri suite comps opts <<<"$entry"
        host=${uri#*://}
        host=${host%%/*}
        for pattern in "${foreign[@]}"; do
            [[ -n $pattern ]] || continue
            if [[ $host == "$pattern" || $host == *".${pattern}" ]]; then
                sdb_log_finding high "repo_cross_distribution" "${file}:${lineno}" \
                    "${host} belongs to another distribution and must not be mixed into ${SDB_PLATFORM}"
            fi
        done
    done
    return 0
}

# sdb_audit_suite_consistency: entries pointing at a release other than ours.
sdb_audit_suite_consistency() {
    local entry file lineno _type uri suite comps opts
    local expect=${SDB_OS_CODENAME:-}
    [[ -n $expect ]] || return 0
    # Rolling platforms have no codename expectation.
    case $SDB_PLATFORM in kali|parrot) return 0 ;; esac
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno type uri suite comps opts <<<"$entry"
        case $suite in
            "$expect"|"$expect"-*) continue ;;
            stable|stable-*|oldstable|oldstable-*) continue ;;
            testing|testing-*|unstable|sid|experimental)
                sdb_log_finding high "repo_development_suite" "${file}:${lineno}" \
                    "suite '${suite}' is a development suite on a '${expect}' system" ;;
            *-proposed|*-devel)
                sdb_log_finding high "repo_proposed_suite" "${file}:${lineno}" "suite '${suite}'" ;;
            "")  ;;
            *)
                sdb_log_finding medium "repo_suite_mismatch" "${file}:${lineno}" \
                    "suite '${suite}' does not match detected release '${expect}'" ;;
        esac
    done
    return 0
}

# sdb_audit_apt_conf: hooks, proxies, and verification-weakening options.
sdb_audit_apt_conf() {
    local etc=${SDB_APT_ETC:?} f line lineno
    local -a files=()
    [[ -f "${etc}/apt.conf" ]] && files+=("${etc}/apt.conf")
    if [[ -d "${etc}/apt.conf.d" ]]; then
        while IFS= read -r -d '' f; do files+=("$f"); done \
            < <(sdb_cmd find "${etc}/apt.conf.d" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    for f in "${files[@]:-}"; do
        [[ -n $f && -r $f ]] || continue
        # An executable file in apt.conf.d is never legitimate.
        if [[ -x $f ]]; then
            sdb_log_finding high "apt_conf_executable" "$f" \
                "configuration file has the executable bit set"
        fi
        lineno=0
        while IFS= read -r line || [[ -n $line ]]; do
            lineno=$((lineno + 1))
            line=$(sdb_trim "$line")
            [[ -z $line || $line == '//'* || $line == '#'* ]] && continue
            case ${line} in
                *Pre-Invoke*|*Post-Invoke*)
                    sdb_log_finding high "apt_hook" "${f}:${lineno}" \
                        "APT invokes a shell command: ${line}" ;;
                *Acquire::*[Pp]roxy*)
                    sdb_log_finding medium "apt_proxy" "${f}:${lineno}" "${line}" ;;
                *AllowUnauthenticated*[Tt]rue*|*AllowInsecureRepositories*[Tt]rue*|\
                *AllowDowngradeToInsecureRepositories*[Tt]rue*)
                    sdb_log_finding high "apt_verification_disabled" "${f}:${lineno}" "${line}" ;;
                *Acquire::Check-Valid-Until*[Ff]alse*)
                    sdb_log_finding medium "apt_valid_until_disabled" "${f}:${lineno}" "${line}" ;;
                *APT::Get::Force-Yes*[Tt]rue*)
                    sdb_log_finding medium "apt_force_yes" "${f}:${lineno}" "${line}" ;;
                *Dir::Bin::*|*Dir::Etc::*|*Dir::State::*)
                    sdb_log_finding medium "apt_dir_override" "${f}:${lineno}" \
                        "APT directory layout is overridden: ${line}" ;;
            esac
        done <"$f"
    done
    return 0
}

# sdb_audit_pinning: preferences and holds.
sdb_audit_pinning() {
    local etc=${SDB_APT_ETC:?} f held
    local -a files=()
    [[ -f "${etc}/preferences" ]] && files+=("${etc}/preferences")
    if [[ -d "${etc}/preferences.d" ]]; then
        while IFS= read -r -d '' f; do files+=("$f"); done \
            < <(sdb_cmd find "${etc}/preferences.d" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    for f in "${files[@]:-}"; do
        [[ -n $f && -r $f ]] || continue
        sdb_log_finding medium "apt_pinning" "$f" \
            "APT pinning is configured; review it before repair (pinning can hold packages at vulnerable versions)"
    done
    if sdb_have apt-mark; then
        while IFS= read -r held; do
            [[ -n $held ]] && sdb_log_finding medium "package_held" "$held" \
                "package is held and will not receive updates"
        done < <(sdb_cmd apt-mark showhold 2>/dev/null || true)
    fi
    return 0
}

# sdb_audit_methods: non-vendor APT transport methods are code that APT runs.
sdb_audit_methods() {
    local dir="${SDB_SYS_ROOT%/}/usr/lib/apt/methods" m owner
    ((SDB_IS_TERMUX)) && dir="${SDB_PREFIX}/lib/apt/methods"
    [[ -d $dir ]] || return 0
    while IFS= read -r -d '' m; do
        owner=$(_sdb_dpkg_owner "$m")
        [[ $owner == "-" ]] && sdb_log_finding high "apt_custom_method" "$m" \
            "transport method not owned by any installed package"
    done < <(sdb_cmd find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
}

# sdb_audit_unsafe_symlinks: symlinks in APT config that escape the config root.
sdb_audit_unsafe_symlinks() {
    local etc=${SDB_APT_ETC:?} link target root
    root=$etc
    while IFS= read -r -d '' link; do
        local allowed=0 dir
        for dir in "${SDB_KEYRING_DIRS[@]:-}" "$root"; do
            [[ -n $dir ]] || continue
            if sdb_symlink_is_safe "$link" "$dir"; then allowed=1; break; fi
        done
        if ((! allowed)); then
            target=$(sdb_cmd readlink -- "$link" 2>/dev/null || printf '?')
            sdb_log_finding high "unsafe_symlink" "$link" "points outside expected roots: ${target}"
        fi
    done < <(sdb_cmd find "$etc" -type l -print0 2>/dev/null)
}

# sdb_audit_modified_package_files: dpkg's own integrity check.
sdb_audit_modified_package_files() {
    sdb_have dpkg || return 0
    local line
    while IFS= read -r line; do
        [[ -z $line ]] && continue
        case $line in
            *"/etc/apt/"*|*"/usr/share/keyrings/"*)
                sdb_log_finding high "modified_package_file" "${line##* }" \
                    "dpkg --verify reports a change: ${line}" ;;
        esac
    done < <(sdb_cmd dpkg --verify 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# Release status
#
# Data-driven from the target host's distro-info-data where available. The
# fallback table is dated and is used only when that package is absent.
# ---------------------------------------------------------------------------

# Fallback release data, retrieved 2026-08-06 from the build host's
# distro-info-data package (see docs/research-sources.md §3.5, §3.8).
# Format: "<id> <codename> <eol-date-or-rolling>"
readonly SDB_FALLBACK_RELEASES=(
    "debian bullseye 2026-08-31"
    "debian bookworm 2026-09-12"
    "debian trixie   2028-08-09"
    "debian forky    prerelease"
    "debian duke     prerelease"
    "ubuntu focal    2025-05-31"
    "ubuntu jammy    2027-06-01"
    "ubuntu noble    2029-05-31"
    "ubuntu plucky   2026-01-15"
    "ubuntu questing 2026-07-09"
    "ubuntu resolute 2031-05-29"
)
readonly SDB_FALLBACK_RELEASES_DATE="2026-08-06"

# _sdb_release_status_from_distro_info <id> <codename>
_sdb_release_status_from_distro_info() {
    local id=${1:?} codename=${2:?}
    local csv="${SDB_SYS_ROOT%/}/usr/share/distro-info/${id}.csv"
    [[ -r $csv ]] || return 1
    local line version name series created release eol rest today
    today=$(date -u +%F)
    while IFS=, read -r version name series created release eol rest; do
        [[ $series == "$codename" ]] || continue
        if [[ -z $release ]]; then
            SDB_RELEASE_STATUS="prerelease"; SDB_RELEASE_EOL_DATE=""
            return 0
        fi
        if [[ -z $eol ]]; then
            SDB_RELEASE_STATUS="unknown"; SDB_RELEASE_EOL_DATE=""
            return 0
        fi
        SDB_RELEASE_EOL_DATE=$eol
        if [[ $today > $eol ]]; then
            SDB_RELEASE_STATUS="eol"
        else
            SDB_RELEASE_STATUS="supported"
        fi
        return 0
    done <"$csv"
    return 1
}

_sdb_release_status_from_fallback() {
    local id=${1:?} codename=${2:?} row rid rcode reol today
    today=$(date -u +%F)
    for row in "${SDB_FALLBACK_RELEASES[@]}"; do
        # shellcheck disable=SC2086
        set -- $row
        rid=$1; rcode=$2; reol=$3
        [[ $rid == "$id" && $rcode == "$codename" ]] || continue
        if [[ $reol == "prerelease" ]]; then
            SDB_RELEASE_STATUS="prerelease"; return 0
        fi
        SDB_RELEASE_EOL_DATE=$reol
        if [[ $today > $reol ]]; then SDB_RELEASE_STATUS="eol"; else SDB_RELEASE_STATUS="supported"; fi
        sdb_log_warn "release status came from the built-in table dated ${SDB_FALLBACK_RELEASES_DATE};"
        sdb_log_warn "install 'distro-info-data' on this host for authoritative dates"
        return 0
    done
    return 1
}

sdb_release_status() {
    SDB_RELEASE_STATUS="unknown"
    SDB_RELEASE_EOL_DATE=""
    case $SDB_PLATFORM in
        kali|parrot)
            SDB_RELEASE_STATUS="rolling"
            return 0 ;;
        termux)
            SDB_RELEASE_STATUS="rolling"
            return 0 ;;
    esac
    local id=$SDB_OS_ID codename=$SDB_OS_CODENAME
    # MX tracks a Debian base; classify against Debian's calendar.
    [[ $SDB_PLATFORM == "mx-linux" ]] && id="debian"
    [[ -n $codename ]] || return 0
    _sdb_release_status_from_distro_info "$id" "$codename" && return 0
    _sdb_release_status_from_fallback "$id" "$codename" && return 0
    return 0
}

# sdb_require_supported_release: gate for repair.
sdb_require_supported_release() {
    sdb_release_status
    case $SDB_RELEASE_STATUS in
        supported|rolling)
            sdb_log_ok "release status: ${SDB_RELEASE_STATUS}${SDB_RELEASE_EOL_DATE:+ (supported until ${SDB_RELEASE_EOL_DATE})}"
            return 0 ;;
        eol)
            sdb_refuse "$SDB_EX_RELEASE" \
                "rewriting repositories for an end-of-life release" \
                "${SDB_OS_ID} ${SDB_OS_VERSION_ID} (${SDB_OS_CODENAME}) reached end of life on ${SDB_RELEASE_EOL_DATE}; its official repositories no longer carry updates and this tool will not silently point the system at a different release or at archive repositories" \
                "upgrade to a supported release using the vendor's documented procedure, or re-run with --use-archive-repositories if you have accepted the risk of running an unsupported release from archived packages" ;;
        prerelease)
            sdb_refuse "$SDB_EX_RELEASE" \
                "rewriting repositories for a pre-release/development release" \
                "${SDB_OS_CODENAME} has not been released; repository layout for it is not stable" \
                "manage development-release repositories by hand" ;;
        *)
            sdb_refuse "$SDB_EX_RELEASE" \
                "rewriting repositories for an unrecognised release" \
                "could not determine the support status of '${SDB_OS_CODENAME:-<no codename>}' for ${SDB_OS_ID:-unknown}" \
                "install 'distro-info-data', or verify the release by hand and repair the repositories manually" ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
sdb_audit_run() {
    sdb_log_stage "audit"
    sdb_parse_repositories
    sdb_audit_trust_bypass
    sdb_audit_duplicates
    sdb_audit_foreign
    sdb_audit_suite_consistency
    sdb_audit_apt_conf
    sdb_audit_pinning
    sdb_audit_methods
    sdb_audit_unsafe_symlinks
    sdb_audit_modified_package_files
    sdb_release_status
    sdb_log_info "release status: ${SDB_RELEASE_STATUS}${SDB_RELEASE_EOL_DATE:+ (eol ${SDB_RELEASE_EOL_DATE})}"
    sdb_log_info "findings: ${SDB_FINDINGS_HIGH} high, ${SDB_FINDINGS_MEDIUM} medium, ${SDB_FINDINGS_LOW} low"
    sdb_stage_mark "audit"
}
