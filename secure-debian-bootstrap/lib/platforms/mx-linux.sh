#!/usr/bin/env bash
# platforms/mx-linux.sh - MX Linux.
#
# MX deliberately combines MX repositories with Debian stable repositories, so
# Debian archives are EXPECTED here and must not be treated as foreign. Init may
# be SysVinit or systemd (MX 25.1 ships both) and is never assumed.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_MX:-} ]] && return 0
SDB_LIB_PLATFORM_MX=1

SDB_MX_MIRROR=""

sdb_platform_mx_linux_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

sdb_platform_mx_linux_select_template() {
    local etc="${SDB_SYS_ROOT%/}/etc/apt"
    printf '%s\t%s\n' "mx.list" "${etc}/sources.list.d/mx.list"
    printf '%s\t%s\n' "debian.list" "${etc}/sources.list.d/debian.list"
    printf '%s\t%s\n' "debian-stable-updates.list" "${etc}/sources.list.d/debian-stable-updates.list"
}

# MX users commonly run a local or regional mirror. Preserve what the system
# already uses rather than forcing every installation back onto mxrepo.com.
_sdb_mx_discover_mirror() {
    local entry file lineno _type uri suite _rest scheme host
    for entry in "${SDB_REPO_ENTRIES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r file lineno _type uri suite _rest <<<"$entry"
        case $uri in
            */mx/repo*|*/mx/testrepo*) ;;
            *) continue ;;
        esac
        scheme=${uri%%://*}
        host=${uri#*://}
        host=${host%%/*}
        [[ -n $host ]] || continue
        SDB_MX_MIRROR="${scheme}://${host}"
        sdb_log_verbose "preserving MX mirror discovered on this system: ${SDB_MX_MIRROR}"
        return 0
    done
    SDB_MX_MIRROR="http://mxrepo.com"
    sdb_log_warn "could not discover the MX mirror in use; falling back to ${SDB_MX_MIRROR}"
    sdb_log_warn "(this value is secondary-confidence - see templates/mx-linux/TEMPLATE.meta)"
    return 0
}

# MX repositories are keyed on the Debian base codename, not on the MX version.
_sdb_mx_base_codename() {
    local c=${SDB_OS_CODENAME:-}
    # MX's os-release sometimes reports the MX codename; the Debian base is in
    # /etc/debian_version and in DEBIAN_CODENAME when present.
    local dv="${SDB_SYS_ROOT%/}/etc/debian_version"
    case $c in
        bullseye|bookworm|trixie|forky) printf '%s' "$c"; return 0 ;;
    esac
    if [[ -r $dv ]]; then
        local v; read -r v <"$dv" 2>/dev/null || v=""
        case ${v%%.*} in
            11) printf '%s' "bullseye"; return 0 ;;
            12) printf '%s' "bookworm"; return 0 ;;
            13) printf '%s' "trixie"; return 0 ;;
        esac
        case $v in
            */sid|*/*) : ;;
        esac
    fi
    printf '%s' "$c"
}

sdb_platform_mx_linux_render_vars() {
    _sdb_mx_discover_mirror
    local codename
    codename=$(_sdb_mx_base_codename)
    printf '%s\n' "CODENAME=${codename}"
    printf '%s\n' "MX_MIRROR=${SDB_MX_MIRROR}"
}

# Debian is NOT foreign on MX. This is the case the "never mix repositories"
# rule must not be applied naively to.
sdb_platform_mx_linux_foreign_origins() {
    printf '%s\n' \
        "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com" \
        "http.kali.org" "kali.download" "deb.parrot.sh" "packages.termux.dev"
}

sdb_platform_mx_linux_official_hosts() {
    printf '%s\n' \
        "mxrepo.com" "deb.debian.org" "security.debian.org" "ftp.debian.org"
}

sdb_platform_mx_linux_hardening_profile() {
    local -a profile=(
        "package_db_check" "keyring_check" "security_updates" "obsolete_metadata"
        "file_permissions" "ssh_client_config" "ssh_server_config"
        "firewall" "logging" "core_dumps" "tmp_protection"
        "suid_sgid_report" "world_writable_report" "modified_package_files"
        "git_ssh_key_permissions" "unsafe_path_report"
    )
    # auditd/AppArmor integration on MX depends on the init actually running.
    if [[ ${SDB_INIT:-} == "systemd" ]]; then
        profile+=("auditd" "apparmor")
    fi
    printf '%s\n' "${profile[@]}"
}

sdb_platform_mx_linux_preflight() {
    sdb_log_info "MX Linux init system: ${SDB_INIT}"
    if [[ ${SDB_INIT:-} != "systemd" ]]; then
        sdb_log_info "systemd-specific controls will be skipped and recorded as unsupported"
    fi
    local codename
    codename=$(_sdb_mx_base_codename)
    if [[ -z $codename ]]; then
        sdb_refuse "$SDB_EX_DETECT" \
            "repairing MX repositories without a Debian base codename" \
            "neither os-release nor /etc/debian_version yielded a usable codename" \
            "restore /etc/os-release and /etc/debian_version, then re-run"
    fi
    sdb_log_info "MX Debian base codename: ${codename}"
    return 0
}

# See the note in lib/platforms/kali.sh: discovery must run in the parent shell.
sdb_platform_mx_linux_prepare() {
    _sdb_mx_discover_mirror
    return 0
}
