#!/usr/bin/env bash
# platforms/termux.sh - Termux on Android.
#
# Termux is not a Debian installation. Everything lives under $PREFIX, there is
# no systemd, no root is assumed or requested, and no kernel/firewall/PAM/init
# change is attempted - Android does not permit them from Termux.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_TERMUX:-} ]] && return 0
SDB_LIB_PLATFORM_TERMUX=1

sdb_platform_termux_roots() {
    printf '%s\n' "${SDB_PREFIX}/etc/apt"
}

# Which template files to render, as "template-relpath -> destination".
sdb_platform_termux_select_template() {
    printf '%s\t%s\n' "sources.list" "${SDB_PREFIX}/etc/apt/sources.list"
}

sdb_platform_termux_render_vars() {
    :   # the Termux template has no substitutions
}

# Hosts belonging to other distributions. A Debian archive inside Termux's APT
# configuration is always wrong.
sdb_platform_termux_foreign_origins() {
    printf '%s\n' \
        "deb.debian.org" "security.debian.org" "ftp.debian.org" "archive.debian.org" \
        "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com" \
        "http.kali.org" "kali.download" "deb.parrot.sh" "mxrepo.com"
}

sdb_platform_termux_official_hosts() {
    printf '%s\n' "packages.termux.dev" "packages-cf.termux.dev"
}

# Baseline controls that Termux can actually enforce. Everything else is
# recorded as unsupported rather than attempted.
sdb_platform_termux_hardening_profile() {
    printf '%s\n' \
        "package_db_check" \
        "keyring_check" \
        "file_permissions" \
        "ssh_client_config" \
        "git_ssh_key_permissions" \
        "shared_storage_warning"
}

sdb_platform_termux_unsupported_controls() {
    printf '%s\n' \
        "firewall:Android does not permit packet filtering from Termux" \
        "auditd:no kernel audit access from Termux" \
        "apparmor:no LSM control from Termux" \
        "sysctl:kernel parameters are not writable from Termux" \
        "core_dumps:limits are per-session only on Android" \
        "sshd_hardening:only applies if you run sshd inside Termux; handled by ssh_server_config when detected" \
        "fail2ban:no system service manager" \
        "aide:not packaged for Termux" \
        "clamav:not maintained for Termux" \
        "lynis:assumes a Linux distribution layout, results are misleading on Termux"
}

# Termux-specific pre-repair validation.
sdb_platform_termux_preflight() {
    if [[ -z ${SDB_PREFIX:-} ]]; then
        sdb_refuse "$SDB_EX_UNSAFE_PATH" "operating on Termux without a resolved PREFIX" \
            "PREFIX is empty, so no safe write root can be established" \
            "run inside Termux, or set PREFIX to the Termux usr directory"
    fi
    if [[ $SDB_PREFIX != *"/com.termux/files/usr" ]]; then
        sdb_log_warn "PREFIX does not look like a Termux prefix: ${SDB_PREFIX}"
    fi
    # The hard guarantee: Termux must never write into /etc/apt.
    if sdb_path_is_within "${SDB_APT_ETC}" "/etc"; then
        sdb_refuse "$SDB_EX_UNSAFE_PATH" "writing Termux configuration into /etc" \
            "APT root resolved to ${SDB_APT_ETC}, which is outside \$PREFIX" \
            "this is a bug; report it - the tool will not continue"
    fi
    if ((SDB_IS_ROOT)); then
        sdb_log_warn "running as root inside Termux; this tool does not require or use root here"
    fi
    # Keyring presence: Termux verification depends on termux-keyring.
    local kr="${SDB_PREFIX}/etc/apt/trusted.gpg.d"
    if [[ ! -d $kr ]] || ! compgen -G "${kr}/*.gpg" >/dev/null 2>&1; then
        sdb_log_finding high "termux_keyring_missing" "$kr" \
            "no keyring files; apt cannot verify Termux packages. Reinstall termux-keyring."
    fi
    return 0
}

# A Termux keyring entry is normally a symlink into $PREFIX/share/termux-keyring;
# that is expected, not an unsafe symlink.
sdb_platform_termux_symlink_allowlist() {
    printf '%s\n' "${SDB_PREFIX}/share/termux-keyring"
}
