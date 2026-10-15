#!/usr/bin/env bash
# repository-validate.sh - validate the staged configuration before activation.
#
# The staged tree is a complete APT configuration root. We point the real apt
# at it with Dir:: overrides, so the configuration is exercised for real without
# being installed. Keyrings are deliberately NOT redirected: verifying against
# the system's real trust anchors is the property being tested.
#
# If any check fails, nothing is activated, the staging tree is preserved, and
# the failure reason is printed precisely.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_REPO_VALIDATE:-} ]] && return 0
SDB_LIB_REPO_VALIDATE=1

SDB_VALIDATION_LOG=""
SDB_VALIDATION_FAILURES=0

_sdb_vfail() {
    SDB_VALIDATION_FAILURES=$((SDB_VALIDATION_FAILURES + 1))
    sdb_log_error "validation: $*"
    printf 'FAIL: %s\n' "$*" >>"$SDB_VALIDATION_LOG"
}

_sdb_vpass() {
    sdb_log_verbose "validation ok: $*"
    printf 'PASS: %s\n' "$*" >>"$SDB_VALIDATION_LOG"
}

# ---------------------------------------------------------------------------
# Static checks (no apt required)
# ---------------------------------------------------------------------------

sdb_validate_syntax() {
    local entry staged dest line lineno
    for entry in "${SDB_STAGED_FILES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r staged dest <<<"$entry"
        [[ -f $staged ]] || { _sdb_vfail "staged file missing: ${staged}"; continue; }

        lineno=0
        case $dest in
            *.sources)
                local seen_types=0 seen_uris=0 seen_suites=0
                while IFS= read -r line || [[ -n $line ]]; do
                    lineno=$((lineno + 1))
                    line=$(sdb_trim "$line")
                    if [[ -z $line ]]; then
                        # end of a stanza
                        if ((seen_types || seen_uris || seen_suites)); then
                            ((seen_types && seen_uris && seen_suites)) || \
                                _sdb_vfail "${dest}: stanza ending at line ${lineno} is missing Types/URIs/Suites"
                        fi
                        seen_types=0; seen_uris=0; seen_suites=0
                        continue
                    fi
                    [[ $line == '#'* ]] && continue
                    [[ $line == *:* ]] || { _sdb_vfail "${dest}:${lineno}: not a deb822 field: ${line}"; continue; }
                    case ${line,,} in
                        types:*)  seen_types=1 ;;
                        uris:*)   seen_uris=1 ;;
                        suites:*) seen_suites=1 ;;
                    esac
                done <"$staged"
                if ((seen_types || seen_uris || seen_suites)); then
                    ((seen_types && seen_uris && seen_suites)) || \
                        _sdb_vfail "${dest}: final stanza is missing Types/URIs/Suites"
                fi
                ;;
            *.list)
                while IFS= read -r line || [[ -n $line ]]; do
                    lineno=$((lineno + 1))
                    line=$(sdb_trim "$line")
                    [[ -z $line || $line == '#'* ]] && continue
                    [[ $line == deb\ * || $line == deb-src\ * || $line == deb\ \[* ]] || \
                        _sdb_vfail "${dest}:${lineno}: not a valid one-line entry: ${line}"
                done <"$staged"
                ;;
        esac
    done
    ((SDB_VALIDATION_FAILURES == 0)) && _sdb_vpass "syntax"
    return 0
}

# Release/codename and architecture consistency of the staged content.
sdb_validate_consistency() {
    local entry staged dest line suite expect
    expect=${SDB_OS_CODENAME:-}
    case $SDB_PLATFORM in
        kali)   expect=${SDB_KALI_SUITE:-} ;;
        parrot) expect=${SDB_PARROT_SUITE:-} ;;
        termux) return 0 ;;
        mx-linux) expect=$(_sdb_mx_base_codename) ;;
    esac
    [[ -n $expect ]] || { _sdb_vfail "no expected suite could be determined"; return; }

    for entry in "${SDB_STAGED_FILES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r staged dest <<<"$entry"
        while IFS= read -r line || [[ -n $line ]]; do
            line=$(sdb_trim "$line")
            [[ -z $line || $line == '#'* ]] && continue
            suite=""
            if [[ ${line,,} == suites:* ]]; then
                suite=$(sdb_trim "${line#*:}")
            elif [[ $line == deb* ]]; then
                local rest=$line
                [[ $rest == *'['*']'* ]] && rest="${rest%%[*}${rest#*]}"
                # shellcheck disable=SC2086
                set -- $rest
                suite=${3:-}
            fi
            local s
            for s in $suite; do
                [[ -n $s ]] || continue
                case $s in
                    "$expect"|"$expect"-*) ;;
                    *)
                        _sdb_vfail "${dest}: suite '${s}' does not match the expected release '${expect}' - refusing to move this system between releases" ;;
                esac
            done
        done <"$staged"
    done
    ((SDB_VALIDATION_FAILURES == 0)) && _sdb_vpass "release/codename consistency (${expect})"
    return 0
}

# Keyrings referenced by Signed-By must exist, be regular files, be readable by
# root, and not be group/world-writable.
sdb_validate_keyrings() {
    local entry staged dest line keyring mode
    for entry in "${SDB_STAGED_FILES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r staged dest <<<"$entry"
        while IFS= read -r line || [[ -n $line ]]; do
            line=$(sdb_trim "$line")
            case ${line,,} in
                signed-by:*) keyring=$(sdb_trim "${line#*:}") ;;
                *signed-by=*)
                    keyring=${line#*signed-by=}
                    keyring=${keyring%%[]$'\t' ]*} ;;
                *) continue ;;
            esac
            [[ -n $keyring ]] || continue
            local keyring_real
            keyring_real=$(sdb_rooted_path "$keyring")
            if [[ ! -f $keyring_real ]]; then
                _sdb_vfail "${dest}: Signed-By keyring does not exist: ${keyring}"
                continue
            fi
            mode=$(sdb_file_mode "$keyring_real")
            case $mode in
                *[2367]) _sdb_vfail "${dest}: keyring ${keyring} is group/world-writable (mode ${mode})" ;;
                *) _sdb_vpass "keyring ${keyring} (mode ${mode})" ;;
            esac
        done <"$staged"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Live checks against the staged tree
# ---------------------------------------------------------------------------

# Staged APT invocation.
#
# Passing only -o Dir::Etc=... is NOT sufficient isolation: apt has already
# loaded the host's /etc/apt/apt.conf.d by the time command-line options are
# applied, so the host's hooks would appear in a "staged" dump. Writing a
# config file and pointing APT_CONFIG at it makes apt use the staged tree from
# the start. This was verified against apt 2.8.3: host hooks visible with -o
# alone, none via APT_CONFIG.
SDB_APT_STAGE_CONF=""

_sdb_apt_stage_conf() {
    local stage="${SDB_STAGING_DIR}"
    SDB_APT_STAGE_CONF="${SDB_RUN_DIR}/apt-staged.conf"
    {
        printf 'Dir::Etc "%s/etc/apt/";\n' "$stage"
        printf 'Dir::Etc::main "apt.conf";\n'
        printf 'Dir::Etc::parts "apt.conf.d";\n'
        printf 'Dir::Etc::sourcelist "sources.list";\n'
        printf 'Dir::Etc::sourceparts "sources.list.d";\n'
        printf 'Dir::Etc::preferences "preferences";\n'
        printf 'Dir::Etc::preferencesparts "preferences.d";\n'
        printf 'Dir::State::lists "%s/var/lib/apt/lists";\n' "$stage"
        # Trust anchors are deliberately NOT redirected: verifying against the
        # system's real keyrings is the property under test.
        printf 'Acquire::AllowInsecureRepositories "false";\n'
        printf 'Acquire::AllowDowngradeToInsecureRepositories "false";\n'
        printf 'APT::Get::AllowUnauthenticated "false";\n'
        printf 'Debug::NoLocking "true";\n'
    } >"$SDB_APT_STAGE_CONF"
    chmod 0600 -- "$SDB_APT_STAGE_CONF" 2>/dev/null || true
}

# _sdb_apt_staged <apt-command> [args...]
_sdb_apt_staged() {
    local cmd=${1:?}; shift
    [[ -n $SDB_APT_STAGE_CONF ]] || _sdb_apt_stage_conf
    APT_CONFIG="$SDB_APT_STAGE_CONF" sdb_cmd "$cmd" "$@"
}

sdb_validate_apt_config_dump() {
    sdb_have apt-config || { sdb_log_warn "apt-config unavailable; skipping config dump review"; return 0; }
    local dump
    if ! dump=$(_sdb_apt_staged apt-config dump 2>&1); then
        _sdb_vfail "apt-config dump failed against the staged configuration"
        printf '%s\n' "$dump" >>"$SDB_VALIDATION_LOG"
        return 1
    fi
    printf -- '--- apt-config dump (staged) ---\n%s\n' "$dump" >>"$SDB_VALIDATION_LOG"
    # Anything in the dump that weakens verification is a failure.
    local line
    while IFS= read -r line; do
        case ${line,,} in
            *allowinsecurerepositories*\"true\"*|*allowunauthenticated*\"true\"*|\
            *allowdowngradetoinsecurerepositories*\"true\"*)
                _sdb_vfail "staged apt configuration weakens verification: ${line}" ;;
            *pre-invoke*|*post-invoke*)
                _sdb_vfail "staged apt configuration contains an invoke hook: ${line}" ;;
        esac
    done <<<"$dump"
    _sdb_vpass "apt-config dump review"
}

# apt-get indextargets enumerates targets that have actually been acquired, so
# it is only meaningful once a staged update has succeeded. Calling it against
# an empty staged lists directory always returns nothing, which is not evidence
# of a bad configuration (verified against apt 2.8.3).
sdb_validate_indextargets() {
    sdb_have apt-get || return 0
    if ((SDB_STAGED_UPDATE_OK == 0)); then
        printf 'SKIP: apt-get indextargets (no successful staged update to enumerate)\n' \
            >>"$SDB_VALIDATION_LOG"
        return 0
    fi
    local out
    if ! out=$(_sdb_apt_staged apt-get indextargets 2>&1); then
        _sdb_vfail "apt-get indextargets failed: ${out}"
        return 1
    fi
    printf -- '--- apt-get indextargets (staged) ---\n%s\n' "$out" >>"$SDB_VALIDATION_LOG"
    if [[ -z $(sdb_trim "$out") ]]; then
        _sdb_vfail "apt-get indextargets produced no targets after a successful update - the staged configuration defines no usable repository"
        return 1
    fi
    _sdb_vpass "apt-get indextargets"
    return 0
}

# The decisive test: can apt fetch and verify metadata for the staged sources?
sdb_validate_apt_update() {
    sdb_have apt-get || { sdb_log_warn "apt-get unavailable; skipping staged update"; return 0; }
    if ((SDB_NO_NETWORK)); then
        sdb_log_warn "network validation disabled (--no-network); staged configuration was NOT verified against the archives"
        printf 'SKIP: apt-get update (--no-network)\n' >>"$SDB_VALIDATION_LOG"
        return 0
    fi
    local out rc=0
    sdb_log_info "running apt-get update against the staged configuration (live config untouched)"
    out=$(_sdb_apt_staged apt-get update 2>&1) || rc=$?
    printf -- '--- apt-get update (staged) ---\n%s\n' "$out" >>"$SDB_VALIDATION_LOG"

    local line
    while IFS= read -r line; do
        case $line in
            *"NO_PUBKEY"*)
                _sdb_vfail "missing signing key: ${line}" ;;
            *"is not signed"*|*"no longer signed"*)
                _sdb_vfail "unsigned repository metadata: ${line}" ;;
            *"Release file"*"not valid"*|*"Release file"*"expired"*)
                _sdb_vfail "invalid or expired Release file: ${line}" ;;
            *"does not have a Release file"*)
                _sdb_vfail "repository has no Release file: ${line}" ;;
            *"Conflicting distribution"*|*"Codename mismatch"*|*"Suite mismatch"*)
                _sdb_vfail "release mismatch: ${line}" ;;
            *"changed its"*"value from"*)
                _sdb_vfail "repository metadata changed unexpectedly (possible redirection): ${line}" ;;
            *"Could not resolve"*|*"Temporary failure resolving"*|*"Connection failed"*|*"Cannot initiate the connection"*)
                sdb_log_warn "network problem during staged validation: ${line}" ;;
        esac
    done <<<"$out"

    if ((rc != 0)); then
        # Distinguish "the repository is bad" from "the network is down".
        if grep -qE 'Could not resolve|Temporary failure resolving|Connection failed|Cannot initiate the connection|Connection timed out' <<<"$out"; then
            sdb_log_warn "apt-get update failed for network reasons (exit ${rc})"
            sdb_log_warn "the staged configuration could not be proven correct; it will NOT be activated"
            _sdb_vfail "staged apt-get update could not reach the archives; re-run when the network is available, or use --no-network to skip this check knowingly"
        else
            _sdb_vfail "staged apt-get update failed (exit ${rc}); see ${SDB_VALIDATION_LOG}"
        fi
        return 1
    fi
    SDB_STAGED_UPDATE_OK=1
    _sdb_vpass "apt-get update against staged configuration"
    return 0
}

sdb_validate_duplicates_staged() {
    local entry staged dest line uri suite key
    declare -A seen=()
    for entry in "${SDB_STAGED_FILES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r staged dest <<<"$entry"
        local curr_uris="" curr_suites=""
        while IFS= read -r line || [[ -n $line ]]; do
            line=$(sdb_trim "$line")
            if [[ -z $line ]]; then curr_uris=""; curr_suites=""; continue; fi
            [[ $line == '#'* ]] && continue
            case ${line,,} in
                uris:*)   curr_uris=$(sdb_trim "${line#*:}") ;;
                suites:*) curr_suites=$(sdb_trim "${line#*:}") ;;
                deb\ *)
                    local rest=$line
                    [[ $rest == *'['*']'* ]] && rest="${rest%%[*}${rest#*]}"
                    # shellcheck disable=SC2086
                    set -- $rest
                    curr_uris=${2:-}; curr_suites=${3:-} ;;
                *) continue ;;
            esac
            [[ -n $curr_uris && -n $curr_suites ]] || continue
            for uri in $curr_uris; do
                for suite in $curr_suites; do
                    key="${uri%/}|${suite}"
                    if [[ -n ${seen[$key]:-} ]]; then
                        _sdb_vfail "duplicate repository definition in staged output: ${uri} ${suite} (${dest} and ${seen[$key]})"
                    else
                        seen[$key]=$dest
                    fi
                done
            done
        done <"$staged"
    done
    ((SDB_VALIDATION_FAILURES == 0)) && _sdb_vpass "no duplicate definitions"
    return 0
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

: "${SDB_NO_NETWORK:=0}"
SDB_STAGED_UPDATE_OK=0

sdb_validate_run() {
    sdb_log_stage "validate (staged configuration)"
    SDB_VALIDATION_LOG="${SDB_RUN_DIR}/validation.txt"
    SDB_VALIDATION_FAILURES=0
    SDB_STAGED_UPDATE_OK=0
    : >"$SDB_VALIDATION_LOG"
    _sdb_apt_stage_conf

    sdb_validate_syntax
    sdb_validate_consistency
    sdb_validate_keyrings
    sdb_validate_duplicates_staged
    sdb_validate_apt_config_dump || true
    sdb_validate_apt_update || true
    sdb_validate_indextargets || true

    if ((SDB_VALIDATION_FAILURES > 0)); then
        sdb_log_error "staged configuration failed validation with ${SDB_VALIDATION_FAILURES} failure(s)"
        sdb_log_error "NOTHING was activated. The live configuration is unchanged."
        sdb_log_error "staged files kept for inspection: ${SDB_STAGING_DIR}"
        sdb_log_error "validation transcript:            ${SDB_VALIDATION_LOG}"
        sdb_log_event "validation_failed" "failures=${SDB_VALIDATION_FAILURES}"
        return 1
    fi

    sdb_log_ok "staged configuration passed validation"
    sdb_stage_mark "validate"
    return 0
}
