#!/usr/bin/env bash
# preflight.sh - environment sanity checks before anything else happens.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PREFLIGHT:-} ]] && return 0
SDB_LIB_PREFLIGHT=1

readonly SDB_BASH_MIN_MAJOR=4
readonly SDB_BASH_MIN_MINOR=4

# Commands the tool cannot function without at all.
readonly SDB_REQUIRED_CMDS=(cat cp date find grep id install ln mkdir mv readlink rm sed sort stat tr uname)
# Commands that enable specific features; absence degrades, never breaks.
readonly SDB_OPTIONAL_CMDS=(apt-get apt-cache apt-config dpkg dpkg-query gpg gpgv flock sha256sum getfacl setfacl getfattr setfattr sudo systemctl distro-info awk)

sdb_preflight_bash_version() {
    local major=${BASH_VERSINFO[0]:-0} minor=${BASH_VERSINFO[1]:-0}
    if (( major < SDB_BASH_MIN_MAJOR )) || \
       (( major == SDB_BASH_MIN_MAJOR && minor < SDB_BASH_MIN_MINOR )); then
        printf 'secure-debian-bootstrap requires bash >= %s.%s (found %s.%s)\n' \
            "$SDB_BASH_MIN_MAJOR" "$SDB_BASH_MIN_MINOR" "$major" "$minor" >&2
        exit "$SDB_EX_PREFLIGHT"
    fi
    return 0
}

sdb_preflight_commands() {
    local missing=() cmd
    for cmd in "${SDB_REQUIRED_CMDS[@]}"; do
        sdb_resolve_cmd "$cmd" || missing+=("$cmd")
    done
    if ((${#missing[@]} > 0)); then
        sdb_die "$SDB_EX_PREFLIGHT" "missing required commands: ${missing[*]}"
    fi
    for cmd in "${SDB_OPTIONAL_CMDS[@]}"; do
        if sdb_resolve_cmd "$cmd"; then
            sdb_log_debug "optional command available: ${cmd} -> ${SDB_CMD[$cmd]}"
        else
            sdb_log_debug "optional command absent: ${cmd}"
        fi
    done
    return 0
}

# sdb_preflight_environment: refuse to trust a hostile environment.
sdb_preflight_environment() {
    local var
    for var in LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PERL5LIB PYTHONPATH BASH_ENV ENV; do
        if [[ -n ${!var:-} ]]; then
            sdb_log_warn "environment variable ${var} is set; it is ignored by this tool but may affect child processes"
            sdb_log_finding medium "suspicious_environment" "$var" "set in the calling environment"
        fi
    done
    # An unusual PATH is worth recording; we do not rely on it (all commands are
    # resolved to absolute paths), but it is evidence.
    sdb_log_debug "PATH=${PATH}"
    local part
    local IFS=':'
    for part in $PATH; do
        [[ -z $part || $part == '.' ]] && \
            sdb_log_finding medium "unsafe_path_entry" "PATH" "contains an empty or relative element"
        [[ $part == /* ]] || continue
        if [[ -d $part ]]; then
            local mode
            mode=$(sdb_file_mode "$part")
            [[ $mode == *[2367] ]] && [[ ${mode: -1} == [2367] ]] && \
                sdb_log_finding medium "world_writable_path_entry" "$part" "mode=${mode}"
        fi
    done
    IFS=$' \t\n'
}

# sdb_preflight_state_dir <dir>
sdb_preflight_state_dir() {
    local dir=${1:?} parent
    parent=${dir%/*}
    if [[ -e $dir && ! -d $dir ]]; then
        sdb_die "$SDB_EX_PREFLIGHT" "state path exists but is not a directory: ${dir}"
    fi
    if [[ -L $dir ]]; then
        sdb_die "$SDB_EX_UNSAFE_PATH" "state directory is a symlink; refusing: ${dir}"
    fi
    # Termux shared storage does not preserve permissions or ownership.
    case $dir in
        /sdcard/*|/storage/*|*/storage/shared/*)
            sdb_log_warn "state directory is on Android shared storage: ${dir}"
            sdb_log_warn "shared storage does not preserve Unix ownership or permission bits;"
            sdb_log_warn "backups taken there cannot be restored faithfully. Use \$PREFIX/var instead."
            sdb_log_finding high "state_dir_on_shared_storage" "$dir" "permissions cannot be preserved"
            ;;
    esac
    [[ -d $parent ]] || sdb_log_debug "state parent will be created: ${parent}"
    return 0
}

sdb_preflight_apt_root() {
    local etc=${SDB_APT_ETC:?}
    if [[ ! -d $etc ]]; then
        sdb_log_warn "APT configuration directory does not exist: ${etc}"
        sdb_log_finding high "apt_etc_missing" "$etc" "no APT configuration directory"
        return 0
    fi
    if [[ -L $etc ]]; then
        sdb_log_finding high "apt_etc_is_symlink" "$etc" \
            "the APT configuration root itself is a symlink"
        sdb_refuse "$SDB_EX_UNSAFE_PATH" \
            "operating on a symlinked APT configuration root" \
            "${etc} is a symlink, which makes every path below it untrustworthy" \
            "inspect and replace it with a real directory by hand first"
    fi
    return 0
}

sdb_preflight() {
    sdb_log_stage "preflight"
    sdb_preflight_bash_version
    sdb_preflight_commands
    sdb_preflight_environment
    sdb_log_ok "preflight checks passed"
}
