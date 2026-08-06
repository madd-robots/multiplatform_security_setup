#!/usr/bin/env bash
# platforms/generic-debian.sh - Debian-derived distributions we do not know.
#
# Audit-only by design. The presence of apt is not evidence that a system's
# official repositories are the Debian ones, and guessing here is exactly the
# failure mode this project exists to avoid.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PLATFORM_GENERIC:-} ]] && return 0
SDB_LIB_PLATFORM_GENERIC=1

sdb_platform_generic_debian_roots() {
    printf '%s\n' "${SDB_SYS_ROOT%/}/etc/apt"
}

sdb_platform_generic_debian_select_template() {
    sdb_refuse "$SDB_EX_DETECT" \
        "rebuilding repositories for an unrecognised Debian-derived distribution" \
        "this system reports ID='${SDB_OS_ID:-unknown}' (ID_LIKE='${SDB_OS_ID_LIKE:-}'), for which this project has no verified official repository definition. Writing Debian's repositories here could replace the vendor's archive, kernel, and desktop stack." \
        "audit, back up, and report with --audit; to add support, create templates/${SDB_OS_ID:-<id>}/ with a TEMPLATE.meta recording the vendor source, plus lib/platforms/${SDB_OS_ID:-<id>}.sh"
}

sdb_platform_generic_debian_render_vars() {
    :
}

# Without knowing the vendor we cannot say which hosts are foreign, so we
# report cross-distribution hosts as informational rather than as violations.
sdb_platform_generic_debian_foreign_origins() {
    :
}

sdb_platform_generic_debian_official_hosts() {
    :
}

# Report-only controls: nothing that changes system state, because we cannot
# predict this distribution's conventions.
sdb_platform_generic_debian_hardening_profile() {
    printf '%s\n' \
        "package_db_check" "keyring_check" "file_permissions" \
        "suid_sgid_report" "world_writable_report" "modified_package_files" \
        "git_ssh_key_permissions" "unsafe_path_report"
}

sdb_platform_generic_debian_preflight() {
    sdb_log_warn "unrecognised Debian-derived distribution: ID='${SDB_OS_ID:-unknown}' ID_LIKE='${SDB_OS_ID_LIKE:-}'"
    sdb_log_warn "this platform is audit-only: repositories will not be rebuilt"
    return 0
}
