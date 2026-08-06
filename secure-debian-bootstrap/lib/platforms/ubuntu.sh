#!/usr/bin/env bash
# platforms/ubuntu.sh - Ubuntu.
#
# The detected release is preserved. Components are preserved from the system.
# -proposed and development suites are refused. No interim<->LTS movement.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_UBUNTU:-} ]] && return 0
SDB_LIB_PLATFORM_UBUNTU=1

SDB_UBUNTU_COMPONENTS=""
SDB_UBUNTU_BACKPORTS=""

sdb_platform_ubuntu_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

sdb_platform_ubuntu_select_template() {
    local etc="${SDB_SYS_ROOT%/}/etc/apt"
    printf '%s\t%s\n' "ubuntu.sources" "${etc}/sources.list.d/ubuntu.sources"
}

# Preserve the component selection that is already in use. A system running
# only "main universe" must not be silently given restricted and multiverse.
_sdb_ubuntu_discover_components() {
    local entry file lineno _type uri suite comps _rest
    declare -A seen=()
    local -a order=(main universe restricted multiverse)
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite comps _rest <<<"$entry"
        case $uri in
            *archive.ubuntu.com*|*security.ubuntu.com*|*ports.ubuntu.com*) ;;
            *) continue ;;
        esac
        local c
        for c in $comps; do seen[$c]=1; done
        case $suite in
            *-backports) SDB_UBUNTU_BACKPORTS=" @CODENAME@-backports" ;;
        esac
    done
    local out=() c
    for c in "${order[@]}"; do
        [[ -n ${seen[$c]:-} ]] && out+=("$c")
    done
    if ((${#out[@]} == 0)); then
        SDB_UBUNTU_COMPONENTS="main universe restricted multiverse"
        sdb_log_warn "could not recover the component selection from existing configuration;"
        sdb_log_warn "falling back to the Ubuntu default: ${SDB_UBUNTU_COMPONENTS}"
    else
        SDB_UBUNTU_COMPONENTS="${out[*]}"
        sdb_log_verbose "preserving Ubuntu components: ${SDB_UBUNTU_COMPONENTS}"
    fi
    return 0
}

sdb_platform_ubuntu_render_vars() {
    _sdb_ubuntu_discover_components
    local backports=${SDB_UBUNTU_BACKPORTS//@CODENAME@/${SDB_OS_CODENAME}}
    printf '%s\n' "CODENAME=${SDB_OS_CODENAME}"
    printf '%s\n' "COMPONENTS=${SDB_UBUNTU_COMPONENTS}"
    printf '%s\n' "BACKPORTS_SUITE=${backports}"
}

sdb_platform_ubuntu_foreign_origins() {
    printf '%s\n' \
        "deb.debian.org" "security.debian.org" "ftp.debian.org" "archive.debian.org" \
        "http.kali.org" "kali.download" "deb.parrot.sh" "mxrepo.com" "packages.termux.dev"
}

sdb_platform_ubuntu_official_hosts() {
    printf '%s\n' \
        "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com" \
        "old-releases.ubuntu.com"
}

sdb_platform_ubuntu_hardening_profile() {
    printf '%s\n' \
        "package_db_check" "keyring_check" "security_updates" "obsolete_metadata" \
        "file_permissions" "ssh_client_config" "ssh_server_config" \
        "firewall" "logging" "auditd" "apparmor" "core_dumps" "tmp_protection" \
        "suid_sgid_report" "world_writable_report" "modified_package_files" \
        "git_ssh_key_permissions" "unsafe_path_report"
}

sdb_platform_ubuntu_preflight() {
    local kr="${SDB_SYS_ROOT%/}/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    [[ -f $kr ]] || sdb_log_finding high "ubuntu_keyring_missing" "$kr" \
        "the keyring referenced by Signed-By does not exist; install ubuntu-keyring before repairing"

    [[ -n ${SDB_OS_CODENAME:-} ]] || sdb_refuse "$SDB_EX_DETECT" \
        "repairing Ubuntu repositories without a codename" \
        "VERSION_CODENAME is absent from os-release, so the correct suite cannot be determined" \
        "restore /etc/os-release from the base-files package, then re-run"

    # Refuse to carry development suites into a rebuilt configuration.
    local entry file lineno _type uri suite _rest
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite _rest <<<"$entry"
        case $suite in
            *-proposed|*-devel)
                sdb_log_warn "development suite '${suite}' found at ${file}:${lineno}; it will be preserved but never written by this tool" ;;
        esac
    done
    return 0
}

# See the note in lib/platforms/kali.sh: discovery must run in the parent shell.
sdb_platform_ubuntu_prepare() {
    _sdb_ubuntu_discover_components
    return 0
}
