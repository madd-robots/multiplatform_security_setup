#!/usr/bin/env bash
# platforms/parrot.sh - Parrot OS.
#
# Parrot's structure is preserved exactly: main, security via the
# deb.parrot.sh/direct/ host (upstream forbids serving security from mirrors),
# and optional backports. Kali and Debian definitions are never substituted in,
# and security tools are never removed.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_PARROT:-} ]] && return 0
SDB_LIB_PLATFORM_PARROT=1

SDB_PARROT_SUITE=""
: "${SDB_PARROT_ENABLE_BACKPORTS:=0}"

sdb_platform_parrot_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

sdb_platform_parrot_select_template() {
    local etc="${SDB_SYS_ROOT%/}/etc/apt"
    printf '%s\t%s\n' "parrot.list" "${etc}/sources.list.d/parrot.list"
}

# Preserve the release channel the system is actually on. The upstream value
# ("echo" as of the retrieval date) is used only if nothing is discoverable, and
# then only with confirmation, because a wrong suite here would move the system
# between releases.
_sdb_parrot_detect_suite() {
    local entry file lineno _type uri suite _rest
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite _rest <<<"$entry"
        [[ $uri == *parrot* ]] || continue
        # Normalise -security/-backports back to the base suite.
        suite=${suite%-security}
        suite=${suite%-backports}
        [[ -n $suite ]] || continue
        SDB_PARROT_SUITE=$suite
        sdb_log_verbose "preserving detected Parrot suite: ${suite}"
        return 0
    done
    if [[ -n ${SDB_OS_CODENAME:-} ]]; then
        SDB_PARROT_SUITE=$SDB_OS_CODENAME
        sdb_log_info "using Parrot suite from os-release codename: ${SDB_PARROT_SUITE}"
        return 0
    fi
    SDB_PARROT_SUITE="echo"
    sdb_log_warn "could not determine the Parrot suite from this system"
    sdb_log_warn "the template default 'echo' was current at template retrieval (2026-08-06)"
    if ! sdb_confirm "Use suite 'echo' for the rebuilt Parrot repositories?"; then
        sdb_refuse "$SDB_EX_NEEDS_DECISION" \
            "rebuilding Parrot repositories with an unconfirmed suite" \
            "the release channel could not be determined and the operator declined the template default" \
            "verify the current Parrot suite and set SDB_PARROT_SUITE explicitly"
    fi
    return 0
}

sdb_platform_parrot_render_vars() {
    [[ -n $SDB_PARROT_SUITE ]] || _sdb_parrot_detect_suite
    printf '%s\n' "PARROT_SUITE=${SDB_PARROT_SUITE}"
    if ((SDB_PARROT_ENABLE_BACKPORTS)); then
        printf '%s\n' "BACKPORTS_COMMENT="
    else
        printf '%s\n' "BACKPORTS_COMMENT=#"
    fi
    return 0
}

sdb_platform_parrot_foreign_origins() {
    printf '%s\n' \
        "deb.debian.org" "security.debian.org" "ftp.debian.org" "archive.debian.org" \
        "archive.ubuntu.com" "security.ubuntu.com" \
        "http.kali.org" "kali.download" "mxrepo.com" "packages.termux.dev"
}

sdb_platform_parrot_official_hosts() {
    printf '%s\n' "deb.parrot.sh" "archive.parrotsec.org" "mirror.parrot.sh"
}

# Like Kali, Parrot is a security-testing platform: intrusive controls are
# opt-in only.
sdb_platform_parrot_hardening_profile() {
    printf '%s\n' \
        "package_db_check" "keyring_check" "security_updates" \
        "file_permissions" "ssh_client_config" "ssh_server_config" \
        "core_dumps" "suid_sgid_report" "world_writable_report" \
        "git_ssh_key_permissions" "apparmor_status_report" "logging"
}

sdb_platform_parrot_optin_controls() {
    printf '%s\n' \
        "firewall:a restrictive firewall breaks common testing workflows" \
        "sysctl_network:forwarding and raw-socket restrictions break testing tools" \
        "aide:rolling system produces constant AIDE noise"
}

sdb_platform_parrot_preflight() {
    # Parrot uses trusted.gpg.d rather than Signed-By, and this build could not
    # verify the exact keyring filename - so report, never write a Signed-By we
    # cannot substantiate.
    local dir="${SDB_SYS_ROOT%/}/etc/apt/trusted.gpg.d" found=0 f
    if [[ -d $dir ]]; then
        for f in "$dir"/*; do
            [[ -e $f ]] || continue
            case ${f##*/} in
                *parrot*) found=1; break ;;
            esac
        done
    fi
    if ((! found)); then
        sdb_log_finding high "parrot_keyring_missing" "$dir" \
            "no Parrot keyring found in trusted.gpg.d; apt cannot verify Parrot packages. Reinstall parrot-archive-keyring."
    fi
    sdb_log_info "Parrot repositories will keep the deb.parrot.sh/direct/ host for security updates (upstream requirement)"
    return 0
}

# See the note in lib/platforms/kali.sh: discovery must run in the parent shell.
sdb_platform_parrot_prepare() {
    _sdb_parrot_detect_suite
    return 0
}
