#!/usr/bin/env bash
# platforms/kali.sh - Kali Linux, including Kali Purple.
#
# Kali is rolling. The detected branch is preserved; the tool never switches
# between kali-rolling and kali-last-snapshot, never adds Debian archives, and
# never removes security tooling.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_KALI:-} ]] && return 0
SDB_LIB_PLATFORM_KALI=1

SDB_KALI_SUITE=""

sdb_platform_kali_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

# Determine the branch actually in use. Defaults to kali-rolling only when
# nothing can be discovered, and that default is announced.
_sdb_kali_detect_suite() {
    local entry file lineno _type uri suite _rest
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite _rest <<<"$entry"
        [[ $uri == *kali* ]] || continue
        case $suite in
            kali-rolling|kali-last-snapshot)
                SDB_KALI_SUITE=$suite
                sdb_log_verbose "preserving detected Kali branch: ${suite}"
                return 0 ;;
        esac
    done
    SDB_KALI_SUITE="kali-rolling"
    sdb_log_warn "could not determine the Kali branch from existing configuration; using kali-rolling (the vendor default)"
    return 0
}

sdb_platform_kali_select_template() {
    _sdb_kali_detect_suite
    local etc="${SDB_SYS_ROOT%/}/etc/apt"
    # deb822 from Kali 2026.2 onward, or whenever kali.sources already exists.
    if [[ -f "${etc}/sources.list.d/kali.sources" ]] || _sdb_kali_is_2026_2_or_newer; then
        printf '%s\t%s\n' "kali.sources" "${etc}/sources.list.d/kali.sources"
    else
        printf '%s\t%s\n' "sources.list.legacy" "${etc}/sources.list"
    fi
    return 0
}

# Kali versions are YYYY.N. Compare against 2026.2, when kali.sources became
# the default.
_sdb_kali_is_2026_2_or_newer() {
    local v=${SDB_OS_VERSION_ID:-}
    [[ $v =~ ^([0-9]{4})\.([0-9]+)$ ]] || return 1
    local year=${BASH_REMATCH[1]} point=${BASH_REMATCH[2]}
    (( year > 2026 )) && return 0
    (( year == 2026 && point >= 2 )) && return 0
    return 1
}

sdb_platform_kali_render_vars() {
    [[ -n $SDB_KALI_SUITE ]] || _sdb_kali_detect_suite
    printf '%s\n' "KALI_SUITE=${SDB_KALI_SUITE}"
}

sdb_platform_kali_foreign_origins() {
    printf '%s\n' \
        "deb.debian.org" "security.debian.org" "ftp.debian.org" "archive.debian.org" \
        "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com" \
        "deb.parrot.sh" "mxrepo.com" "packages.termux.dev"
}

sdb_platform_kali_official_hosts() {
    printf '%s\n' "http.kali.org" "kali.download" "archive.kali.org" "old.kali.org"
}

# Kali is an authorized security-testing workstation. Controls that would
# impede that role are off by default and require explicit opt-in.
sdb_platform_kali_hardening_profile() {
    printf '%s\n' \
        "package_db_check" \
        "keyring_check" \
        "security_updates" \
        "file_permissions" \
        "ssh_client_config" \
        "ssh_server_config" \
        "core_dumps" \
        "suid_sgid_report" \
        "world_writable_report" \
        "git_ssh_key_permissions" \
        "apparmor_status_report" \
        "logging"
}

sdb_platform_kali_optin_controls() {
    printf '%s\n' \
        "firewall:a restrictive firewall breaks common testing workflows on Kali" \
        "sysctl_network:forwarding and raw-socket restrictions break testing tools" \
        "fail2ban:only meaningful if this host exposes services" \
        "aide:high-churn rolling system produces constant AIDE noise"
}

sdb_platform_kali_preflight() {
    if [[ $SDB_VARIANT == "purple" ]]; then
        sdb_log_info "Kali Purple detected; treated as Kali (no branch or distribution change will be made)"
    fi
    local kr="${SDB_SYS_ROOT%/}/usr/share/keyrings/kali-archive-keyring.gpg"
    if [[ ! -f $kr ]]; then
        sdb_log_finding high "kali_keyring_missing" "$kr" \
            "the keyring referenced by Signed-By does not exist; install kali-archive-keyring before repairing"
    fi
    # Warn (do not act) about extra branches.
    local entry file lineno _type uri suite _rest
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite _rest <<<"$entry"
        case $suite in
            kali-experimental|kali-bleeding-edge)
                sdb_log_warn "additional Kali branch in use: ${suite} (${file}:${lineno})"
                sdb_log_warn "this tool preserves it but will not manage it; use kali-tweaks" ;;
        esac
    done
    return 0
}

# sdb_platform_kali_prepare: establish platform state in the parent shell.
# render_vars is captured through a subshell, so any variable it sets would be
# discarded; discovery must happen here.
sdb_platform_kali_prepare() {
    _sdb_kali_detect_suite
    return 0
}
