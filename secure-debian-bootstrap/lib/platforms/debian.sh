#!/usr/bin/env bash
# platforms/debian.sh - Debian proper.
#
# Suite must equal the detected codename. testing/unstable/sid/experimental are
# refused as repair targets. The template is secondary-confidence, so activation
# additionally requires --allow-secondary-template.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_DEBIAN:-} ]] && return 0
SDB_LIB_PLATFORM_DEBIAN=1

SDB_DEBIAN_COMPONENTS=""

sdb_platform_debian_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

sdb_platform_debian_select_template() {
    local etc="${SDB_SYS_ROOT%/}/etc/apt"
    if [[ -f "${etc}/sources.list.d/debian.sources" ]] || _sdb_debian_apt_supports_deb822; then
        printf '%s\t%s\n' "debian.sources" "${etc}/sources.list.d/debian.sources"
    else
        printf '%s\t%s\n' "sources.list.legacy" "${etc}/sources.list"
    fi
    return 0
}

# deb822 has been supported since apt 1.1, but it only became the *shipped*
# default with Debian 13. Follow what the system already does rather than
# migrating it as a side effect of a repair.
_sdb_debian_apt_supports_deb822() {
    local major=${SDB_OS_VERSION_ID%%.*}
    [[ $major =~ ^[0-9]+$ ]] || return 1
    (( major >= 13 ))
}

_sdb_debian_discover_components() {
    local entry file lineno _type uri suite comps _rest
    declare -A seen=()
    local -a order=(main contrib non-free non-free-firmware)
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite comps _rest <<<"$entry"
        case $uri in
            *deb.debian.org*|*security.debian.org*|*ftp*.debian.org*) ;;
            *) continue ;;
        esac
        local c
        for c in $comps; do seen[$c]=1; done
    done
    local out=() c
    for c in "${order[@]}"; do
        [[ -n ${seen[$c]:-} ]] && out+=("$c")
    done
    if ((${#out[@]} == 0)); then
        SDB_DEBIAN_COMPONENTS="main"
        sdb_log_warn "could not recover the component selection; falling back to 'main' only"
        sdb_log_warn "(the conservative choice: it never enables non-free content you did not have)"
    else
        SDB_DEBIAN_COMPONENTS="${out[*]}"
        sdb_log_verbose "preserving Debian components: ${SDB_DEBIAN_COMPONENTS}"
    fi
    return 0
}

sdb_platform_debian_render_vars() {
    _sdb_debian_discover_components
    printf '%s\n' "CODENAME=${SDB_OS_CODENAME}"
    printf '%s\n' "COMPONENTS=${SDB_DEBIAN_COMPONENTS}"
}

sdb_platform_debian_foreign_origins() {
    printf '%s\n' \
        "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com" \
        "http.kali.org" "kali.download" "deb.parrot.sh" "mxrepo.com" "packages.termux.dev"
}

sdb_platform_debian_official_hosts() {
    printf '%s\n' \
        "deb.debian.org" "security.debian.org" "ftp.debian.org" \
        "ftp.us.debian.org" "ftp.uk.debian.org" "ftp.de.debian.org" "archive.debian.org"
}

sdb_platform_debian_hardening_profile() {
    printf '%s\n' \
        "package_db_check" "keyring_check" "security_updates" "obsolete_metadata" \
        "file_permissions" "ssh_client_config" "ssh_server_config" \
        "firewall" "logging" "auditd" "apparmor" "core_dumps" "tmp_protection" \
        "suid_sgid_report" "world_writable_report" "modified_package_files" \
        "git_ssh_key_permissions" "unsafe_path_report"
}

sdb_platform_debian_preflight() {
    local kr="${SDB_SYS_ROOT%/}/usr/share/keyrings/debian-archive-keyring.gpg"
    [[ -f $kr ]] || sdb_log_finding high "debian_keyring_missing" "$kr" \
        "the keyring referenced by Signed-By does not exist; install debian-archive-keyring before repairing"

    case ${SDB_OS_CODENAME:-} in
        ""|sid|unstable|testing|experimental)
            sdb_refuse "$SDB_EX_RELEASE" \
                "rewriting repositories for '${SDB_OS_CODENAME:-<none>}'" \
                "this tool only repairs released, named Debian suites; rolling development suites change too quickly for a fixed template to be safe" \
                "manage testing/unstable repositories by hand" ;;
    esac
    return 0
}

# See the note in lib/platforms/kali.sh: discovery must run in the parent shell.
sdb_platform_debian_prepare() {
    _sdb_debian_discover_components
    return 0
}
