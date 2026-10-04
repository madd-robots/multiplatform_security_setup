#!/usr/bin/env bash
# common.sh - foundation: strict mode, path safety, atomic writes, locking,
# workspace management, plan/apply bookkeeping, privilege helpers.
#
# This file is sourced, never executed. It must not perform any action at
# source time other than defining functions and default variables.
#
# Minimum bash: 4.4
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_COMMON:-} ]] && return 0
SDB_LIB_COMMON=1

# ---------------------------------------------------------------------------
# Exit codes (documented in docs/architecture.md)
#
# ShellCheck cannot see cross-file use in a sourced library, so it reports these
# as unused. That is the one narrowly-justified exception in this project.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034
readonly SDB_EX_OK=0
readonly SDB_EX_FAIL=1
readonly SDB_EX_USAGE=2
readonly SDB_EX_DETECT=3
readonly SDB_EX_PREFLIGHT=4
readonly SDB_EX_BACKUP=5
readonly SDB_EX_VALIDATE=6
readonly SDB_EX_RELEASE=7
readonly SDB_EX_UNSAFE_PATH=8
readonly SDB_EX_NEEDS_DECISION=9
readonly SDB_EX_ROLLBACK=10
readonly SDB_EX_FINDINGS=11
readonly SDB_EX_LOCKED=12

# ---------------------------------------------------------------------------
# Global defaults. Anything an operator may override lives in config/defaults.conf
# ---------------------------------------------------------------------------
: "${SDB_MODE:=audit}"
: "${SDB_DRY_RUN:=0}"
: "${SDB_ASSUME_YES:=0}"
: "${SDB_NON_INTERACTIVE:=0}"
: "${SDB_VERBOSE:=0}"
: "${SDB_DEBUG:=0}"
: "${SDB_STRICT:=0}"
: "${SDB_ALLOW_SECONDARY_TEMPLATE:=0}"
: "${SDB_USE_ARCHIVE_REPOSITORIES:=0}"
: "${SDB_MIN_CONFIDENCE:=70}"

# Populated by detect-platform.sh. These use `:=` so that a caller (or a test
# harness pointing the tool at a fixture) can set them in the environment
# without the library resetting them.
: "${SDB_PLATFORM:=}"
: "${SDB_SYS_ROOT:=}"
: "${SDB_APT_ETC:=}"
: "${SDB_PREFIX:=}"
# Directories this run is permitted to write into. Empty until detection
# completes, which makes any pre-detection write attempt a hard error.
declare -ga SDB_WRITE_ROOTS=()
: "${SDB_STATE_DIR:=}"

# Populated by sdb_init_workspace
SDB_RUN_ID=""
SDB_RUN_DIR=""
SDB_STAGING_DIR=""
SDB_TMP_DIR=""
SDB_LOCK_FILE=""
SDB_LOCK_FD=""
SDB_LOCK_DIR=""

# Populated by backup.sh
SDB_BACKUP_ID=""
SDB_BACKUP_DIR=""

# Plan entries: "action<TAB>target<TAB>detail"
declare -ga SDB_PLAN=()
# Applied entries, same shape.
declare -ga SDB_APPLIED=()

# Resolved absolute paths of external commands, keyed by command name.
declare -gA SDB_CMD=()

# ---------------------------------------------------------------------------
# Strict mode and traps
# ---------------------------------------------------------------------------

# sdb_strict_mode: enable defensive shell options. Called by the launcher.
sdb_strict_mode() {
    set -Eeuo pipefail
    umask 077
    # Do not inherit a hostile IFS.
    IFS=$' \t\n'
    # Do not let the environment redirect command lookup.
    unset CDPATH BASH_ENV ENV GLOBIGNORE 2>/dev/null || true
    shopt -s nullglob
    shopt -u expand_aliases
}

# sdb_on_error <line> <command> <code>
sdb_on_error() {
    local line=$1 cmd=$2 code=$3
    # Avoid recursion if logging itself failed.
    if declare -F sdb_log_error >/dev/null 2>&1; then
        sdb_log_error "unhandled error at line ${line} (exit ${code}): ${cmd}"
    else
        printf '[ERROR] unhandled error at line %s (exit %s): %s\n' \
            "$line" "$code" "$cmd" >&2
    fi
    return 0
}

# sdb_on_exit: cleanup trap. Removes only the per-run temp directory, never
# backups, never quarantine, never staging (staging is preserved deliberately
# so a failed validation can be inspected).
sdb_on_exit() {
    local code=$?
    if [[ -n ${SDB_TMP_DIR:-} && -d ${SDB_TMP_DIR:-} ]]; then
        sdb_safe_remove "$SDB_TMP_DIR" "$SDB_RUN_DIR" || true
    fi
    sdb_release_lock || true
    return "$code"
}

sdb_install_traps() {
    trap 'sdb_on_error "$LINENO" "$BASH_COMMAND" "$?"' ERR
    trap 'sdb_on_exit' EXIT
    trap 'sdb_die "$SDB_EX_FAIL" "interrupted by signal"' INT TERM
}

# sdb_die <code> <message...>
sdb_die() {
    local code=$1; shift
    trap - ERR
    if declare -F sdb_log_error >/dev/null 2>&1; then
        sdb_log_error "$*"
    else
        printf '[ERROR] %s\n' "$*" >&2
    fi
    exit "$code"
}

# ---------------------------------------------------------------------------
# Command resolution. PATH is not trusted: every external command is resolved
# once, to an absolute path, and invoked through that path.
# ---------------------------------------------------------------------------

# sdb_resolve_cmd <name> [<name>...] -> populates SDB_CMD; returns 1 if any missing
sdb_resolve_cmd() {
    local name path rc=0
    for name in "$@"; do
        if [[ -n ${SDB_CMD[$name]:-} ]]; then
            continue
        fi
        if path=$(command -v -- "$name" 2>/dev/null) && [[ -x $path ]]; then
            SDB_CMD[$name]=$path
        else
            rc=1
        fi
    done
    return "$rc"
}

# sdb_have <name> -> 0 if the command is available
sdb_have() {
    [[ -n ${SDB_CMD[$1]:-} ]] || sdb_resolve_cmd "$1"
}

# sdb_cmd <name> [args...] -> run a resolved command by absolute path
sdb_cmd() {
    local name=$1; shift
    local path=${SDB_CMD[$name]:-}
    if [[ -z $path ]]; then
        sdb_resolve_cmd "$name" || sdb_die "$SDB_EX_PREFLIGHT" "required command not found: ${name}"
        path=${SDB_CMD[$name]}
    fi
    "$path" "$@"
}

# ---------------------------------------------------------------------------
# Path safety
#
# These functions are the single choke point protecting against traversal,
# empty/unset expansion, root-level operations, and writes outside the detected
# platform's roots. Every write in this project passes through them.
# ---------------------------------------------------------------------------

# Absolute paths that must never be a write or removal target, directly.
readonly SDB_FORBIDDEN_PATHS=(
    "/" "/bin" "/boot" "/dev" "/etc" "/home" "/lib" "/lib32" "/lib64"
    "/proc" "/root" "/run" "/sbin" "/srv" "/sys" "/tmp" "/usr" "/var"
    "/usr/bin" "/usr/lib" "/usr/local" "/usr/sbin" "/usr/share"
    "/var/lib" "/var/log" "/var/tmp" "/data" "/data/data" "/sdcard"
)

# sdb_path_is_absolute <path>
sdb_path_is_absolute() {
    [[ ${1:-} == /* ]]
}

# sdb_path_normalise <path> -> lexically normalised path on stdout.
# Purely lexical: does not touch the filesystem, so it is safe on paths that
# may not exist and cannot be raced.
sdb_path_normalise() {
    local path=${1:-} out=() part
    [[ -z $path ]] && return 1
    local -a parts=()
    local IFS='/'
    read -r -a parts <<<"$path"
    IFS=$' \t\n'
    for part in "${parts[@]}"; do
        case $part in
            ''|'.') continue ;;
            '..')
                if ((${#out[@]} > 0)); then
                    unset 'out[-1]'
                    out=("${out[@]}")
                fi
                ;;
            *) out+=("$part") ;;
        esac
    done
    if [[ $path == /* ]]; then
        printf '/%s\n' "$(IFS='/'; printf '%s' "${out[*]}")"
    else
        printf '%s\n' "$(IFS='/'; printf '%s' "${out[*]}")"
    fi
}

# sdb_path_is_within <candidate> <root> -> 0 if candidate is root or below it.
# Lexical comparison on normalised paths; both must be absolute.
sdb_path_is_within() {
    local candidate root
    candidate=$(sdb_path_normalise "${1:-}") || return 1
    root=$(sdb_path_normalise "${2:-}") || return 1
    [[ $candidate == /* && $root == /* ]] || return 1
    [[ $root == "/" ]] && return 1   # "within /" is not a meaningful guard
    [[ $candidate == "$root" || $candidate == "$root"/* ]]
}

# sdb_path_is_forbidden <path> -> 0 if the path is a protected system directory
sdb_path_is_forbidden() {
    local path forbidden
    path=$(sdb_path_normalise "${1:-}") || return 0   # unparseable => forbidden
    [[ -z $path ]] && return 0
    for forbidden in "${SDB_FORBIDDEN_PATHS[@]}"; do
        [[ $path == "$forbidden" ]] && return 0
    done
    return 1
}

# sdb_assert_safe_target <path> [<must-be-within-root>]
# Rejects: empty, relative, unnormalised traversal, forbidden system dirs, and
# (when a root is given) anything outside that root.
sdb_assert_safe_target() {
    local path=${1:-} root=${2:-} norm
    if [[ -z $path ]]; then
        sdb_die "$SDB_EX_UNSAFE_PATH" "refusing to operate on an empty path"
    fi
    if ! sdb_path_is_absolute "$path"; then
        sdb_die "$SDB_EX_UNSAFE_PATH" "refusing to operate on a relative path: ${path}"
    fi
    norm=$(sdb_path_normalise "$path")
    if [[ $norm != "$path" && "${path%/}" != "$norm" ]]; then
        sdb_die "$SDB_EX_UNSAFE_PATH" \
            "refusing to operate on a non-normalised path: ${path} (normalises to ${norm})"
    fi
    if sdb_path_is_forbidden "$norm"; then
        sdb_die "$SDB_EX_UNSAFE_PATH" "refusing to operate on protected path: ${norm}"
    fi
    if [[ -n $root ]] && ! sdb_path_is_within "$norm" "$root"; then
        sdb_die "$SDB_EX_UNSAFE_PATH" "refusing to operate outside ${root}: ${norm}"
    fi
    return 0
}

# sdb_manifest_path_is_safe <relative-path>
# Validates a path read from a backup/quarantine manifest before it is used to
# build a destination. Rejects absolute paths, traversal, empty components,
# leading dashes, and newlines/tabs.
sdb_manifest_path_is_safe() {
    local rel=${1-}
    [[ -n $rel ]] || return 1
    [[ $rel == /* ]] && return 1
    [[ $rel == *$'\n'* || $rel == *$'\t'* ]] && return 1
    [[ $rel == -* ]] && return 1
    local -a parts=()
    local IFS='/' part
    read -r -a parts <<<"$rel"
    IFS=$' \t\n'
    for part in "${parts[@]}"; do
        case $part in
            ''|'.'|'..') return 1 ;;
        esac
    done
    return 0
}

# sdb_guard_write_root <path>
# Asserts that a write target is inside one of the roots the detected platform
# declared. This is what keeps Termux out of /etc/apt and everyone else out of
# $PREFIX. SDB_WRITE_ROOTS is set by detect-platform.sh.
sdb_guard_write_root() {
    local path=${1:-} root
    [[ -n $path ]] || sdb_die "$SDB_EX_UNSAFE_PATH" "empty write target"
    if ((${#SDB_WRITE_ROOTS[@]} == 0)); then
        sdb_die "$SDB_EX_UNSAFE_PATH" \
            "no write roots declared (platform detection did not complete): ${path}"
    fi
    for root in "${SDB_WRITE_ROOTS[@]}"; do
        if sdb_path_is_within "$path" "$root"; then
            return 0
        fi
    done
    sdb_die "$SDB_EX_UNSAFE_PATH" \
        "write target outside declared roots for platform '${SDB_PLATFORM}': ${path}"
}

# sdb_symlink_is_safe <path> <allowed-root>
# A symlink is safe when its target, resolved lexically against its own
# directory, stays inside the allowed root. We do not use `readlink -f` here
# because that resolves through the filesystem and is race-prone.
sdb_symlink_is_safe() {
    local link=${1:-} root=${2:-} target dir resolved
    [[ -L $link ]] || return 0
    target=$(sdb_cmd readlink -- "$link" 2>/dev/null) || return 1
    if [[ $target == /* ]]; then
        resolved=$(sdb_path_normalise "$target")
    else
        dir=${link%/*}
        resolved=$(sdb_path_normalise "${dir}/${target}")
    fi
    sdb_path_is_within "$resolved" "$root"
}

# sdb_safe_remove <path> <required-root>
# The only removal primitive in the project. Refuses anything not strictly
# inside required-root, refuses forbidden paths, and refuses symlinked targets.
sdb_safe_remove() {
    local path=${1:-} root=${2:-}
    [[ -n $path && -n $root ]] || return 1
    [[ -e $path || -L $path ]] || return 0
    sdb_assert_safe_target "$path" "$root"
    if [[ -L $path ]]; then
        sdb_cmd rm -f -- "$path"
        return 0
    fi
    sdb_cmd rm -rf -- "$path"
}

# ---------------------------------------------------------------------------
# Atomic file installation
# ---------------------------------------------------------------------------

# sdb_install_file <src> <dest> [<mode>]
# Atomic same-directory rename. Never writes into the destination in place, so
# a crash can never leave a half-written APT source file active.
sdb_install_file() {
    local src=${1:?} dest=${2:?} mode=${3:-0644}
    local dir=${dest%/*} tmp
    sdb_assert_safe_target "$dest"
    sdb_guard_write_root "$dest"
    [[ -f $src ]] || sdb_die "$SDB_EX_FAIL" "source file missing: ${src}"

    if ((SDB_DRY_RUN)); then
        sdb_plan_add "install" "$dest" "mode=${mode} from=${src}"
        return 0
    fi

    sdb_privileged_mkdir "$dir" 0755
    tmp="${dest}.sdb-tmp.$$"
    # install(1) creates with the requested mode from the start; no window
    # exists where the file is world-writable.
    sdb_privileged install -m "$mode" -- "$src" "$tmp"
    sdb_privileged mv -f -- "$tmp" "$dest"
    sdb_applied_add "install" "$dest" "mode=${mode}"
}

# sdb_write_file <dest> <mode> < content-on-stdin
sdb_write_file() {
    local dest=${1:?} mode=${2:-0644} tmp
    tmp="${SDB_TMP_DIR:?}/write.$$"
    cat >"$tmp"
    sdb_install_file "$tmp" "$dest" "$mode"
    rm -f -- "$tmp"
}

# ---------------------------------------------------------------------------
# Privilege
#
# Rules (docs/threat-model.md §6):
#   - never `sudo sh -c "<interpolated>"`
#   - never `sudo -E` (environment is not carried across the boundary)
#   - announce the exact command before escalating
# ---------------------------------------------------------------------------

SDB_IS_ROOT=0
SDB_SUDO=""

sdb_init_privilege() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        SDB_IS_ROOT=1
        SDB_SUDO=""
        return 0
    fi
    SDB_IS_ROOT=0
    # Termux never escalates (docs/supported-platforms.md).
    if [[ ${SDB_PLATFORM:-} == "termux" ]]; then
        SDB_SUDO=""
        return 0
    fi
    if sdb_have sudo; then
        SDB_SUDO=${SDB_CMD[sudo]}
    else
        SDB_SUDO=""
    fi
    return 0
}

# File-manipulation commands that are safe to attempt unprivileged first: if
# the current user already owns the target, no escalation is needed at all, and
# re-running them after a failure has no partial effect.
readonly SDB_UNPRIV_FIRST_CMDS=(install mkdir cp mv rm ln chmod chown touch rmdir)

# sdb_privileged <cmd> [args...]
# Runs with elevation only if needed and available. The argument vector is
# passed through unchanged - no string interpolation, no shell.
sdb_privileged() {
    local cmd=${1:?}; shift
    local path=${SDB_CMD[$cmd]:-}
    if [[ -z $path ]]; then
        sdb_resolve_cmd "$cmd" || sdb_die "$SDB_EX_PREFLIGHT" "required command not found: ${cmd}"
        path=${SDB_CMD[$cmd]}
    fi
    if ((SDB_IS_ROOT)); then
        "$path" "$@"
        return
    fi
    # Try without privilege first where that is safe. This is what keeps the
    # privileged command set minimal (docs/threat-model.md section 6): a run
    # inside $PREFIX, a user-owned state directory, or a test fixture never
    # escalates at all.
    if sdb_in_list "$cmd" "${SDB_UNPRIV_FIRST_CMDS[@]}"; then
        if "$path" "$@" 2>/dev/null; then
            return 0
        fi
    fi
    if [[ -z $SDB_SUDO ]]; then
        sdb_die "$SDB_EX_PREFLIGHT" \
            "operation requires privilege but no usable sudo is available: ${cmd} $*"
    fi
    sdb_log_info "escalating: sudo ${path} $*"
    "$SDB_SUDO" -n -- "$path" "$@" 2>/dev/null || {
        if ((SDB_NON_INTERACTIVE)); then
            sdb_die "$SDB_EX_NEEDS_DECISION" \
                "sudo requires a password but --non-interactive was requested: ${cmd}"
        fi
        "$SDB_SUDO" -- "$path" "$@"
    }
}

sdb_privileged_mkdir() {
    local dir=${1:?} mode=${2:-0755}
    [[ -d $dir ]] && return 0
    sdb_assert_safe_target "$dir"
    sdb_privileged install -d -m "$mode" -- "$dir"
}

# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------

sdb_acquire_lock() {
    local lockdir=${1:?}
    SDB_LOCK_FILE="${lockdir}/lock"
    SDB_LOCK_DIR="${lockdir}/lock.d"

    if sdb_have flock; then
        # A fixed descriptor (not {var}) so the lock can be closed with a plain
        # `exec 9>&-`. The alternative, `eval "exec ${fd}>&-"`, would be the
        # only eval in the project, and "no eval" is a gate in tools/shellcheck.sh.
        exec 9>"$SDB_LOCK_FILE" || \
            sdb_die "$SDB_EX_PREFLIGHT" "cannot create lock file: ${SDB_LOCK_FILE}"
        SDB_LOCK_FD=9
        if ! sdb_cmd flock -n "$SDB_LOCK_FD"; then
            sdb_die "$SDB_EX_LOCKED" \
                "another secure-debian-bootstrap run holds the lock (${SDB_LOCK_FILE})"
        fi
        printf '%s\n' "$$" >&"$SDB_LOCK_FD"
        return 0
    fi

    # Fallback: atomic mkdir with liveness check.
    if mkdir -- "$SDB_LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" >"${SDB_LOCK_DIR}/pid"
        return 0
    fi
    local holder=""
    if [[ -r "${SDB_LOCK_DIR}/pid" ]]; then
        read -r holder <"${SDB_LOCK_DIR}/pid" || holder=""
    fi
    if [[ -n $holder ]] && kill -0 "$holder" 2>/dev/null; then
        sdb_die "$SDB_EX_LOCKED" "another run (pid ${holder}) holds the lock"
    fi
    sdb_die "$SDB_EX_LOCKED" \
        "stale lock at ${SDB_LOCK_DIR} (holder pid '${holder}' not running); remove it after confirming no run is active"
}

sdb_release_lock() {
    if [[ -n ${SDB_LOCK_FD:-} ]]; then
        exec 9>&- 2>/dev/null || true
        SDB_LOCK_FD=""
    fi
    if [[ -n ${SDB_LOCK_DIR:-} && -d ${SDB_LOCK_DIR:-} ]]; then
        rm -f -- "${SDB_LOCK_DIR}/pid" 2>/dev/null || true
        rmdir -- "$SDB_LOCK_DIR" 2>/dev/null || true
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------

sdb_generate_run_id() {
    local stamp rand
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    if [[ -r /dev/urandom ]]; then
        rand=$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c 8) || rand=""
    fi
    [[ -n ${rand:-} && ${#rand} -eq 8 ]] || rand=$(printf '%08x' "$$")
    printf '%s-%s\n' "$stamp" "$rand"
}

# sdb_init_workspace <state-dir>
sdb_init_workspace() {
    local state=${1:?}
    sdb_assert_safe_target "$state"

    SDB_RUN_ID=$(sdb_generate_run_id)
    SDB_STATE_DIR=$state
    SDB_RUN_DIR="${state}/runs/${SDB_RUN_ID}"
    SDB_STAGING_DIR="${SDB_RUN_DIR}/staging"

    local d
    for d in "$state" "${state}/runs" "${state}/backups" "${state}/quarantine" \
             "$SDB_RUN_DIR" "${SDB_RUN_DIR}/stages" "$SDB_STAGING_DIR"; do
        # mkdir -m with -p only applies the mode to the deepest component, so the
        # mode is set explicitly afterwards (SC2174).
        if ! mkdir -p -- "$d" 2>/dev/null; then
            sdb_privileged_mkdir "$d" 0700
        else
            chmod 0700 -- "$d" 2>/dev/null || true
        fi
    done

    SDB_TMP_DIR=$(mktemp -d "${SDB_RUN_DIR}/tmp.XXXXXXXX") || \
        sdb_die "$SDB_EX_PREFLIGHT" "cannot create temporary directory under ${SDB_RUN_DIR}"
    chmod 0700 -- "$SDB_TMP_DIR"
    return 0
}

# ---------------------------------------------------------------------------
# Stage markers - resumability and idempotence
# ---------------------------------------------------------------------------

sdb_stage_done() {
    [[ -f "${SDB_RUN_DIR}/stages/${1:?}.done" ]]
}

sdb_stage_mark() {
    local stage=${1:?}
    ((SDB_DRY_RUN)) && return 0
    printf '%s\n' "$(date -u +%FT%TZ)" >"${SDB_RUN_DIR}/stages/${stage}.done"
}

# ---------------------------------------------------------------------------
# Plan / applied bookkeeping
# ---------------------------------------------------------------------------

sdb_plan_add() {
    local action=${1:?} target=${2:?} detail=${3:-}
    SDB_PLAN+=("${action}"$'\t'"${target}"$'\t'"${detail}")
    sdb_log_debug "plan: ${action} ${target} ${detail}"
}

sdb_applied_add() {
    local action=${1:?} target=${2:?} detail=${3:-}
    SDB_APPLIED+=("${action}"$'\t'"${target}"$'\t'"${detail}")
    sdb_log_event "applied" "action=${action}" "target=${target}" "detail=${detail}"
}

sdb_plan_flush() {
    local entry
    : >"${SDB_RUN_DIR}/plan.txt"
    for entry in "${SDB_PLAN[@]:-}"; do
        [[ -n $entry ]] && printf '%s\n' "$entry" >>"${SDB_RUN_DIR}/plan.txt"
    done
    return 0
}

sdb_applied_flush() {
    local entry
    : >"${SDB_RUN_DIR}/applied.tsv"
    for entry in "${SDB_APPLIED[@]:-}"; do
        [[ -n $entry ]] && printf '%s\n' "$entry" >>"${SDB_RUN_DIR}/applied.tsv"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Confirmation
#
# --yes answers routine questions. It deliberately cannot answer the questions
# listed in docs/threat-model.md T5 - those call sdb_refuse instead.
# ---------------------------------------------------------------------------

# sdb_confirm <question> -> 0 = yes
sdb_confirm() {
    local question=${1:?} reply=""
    if ((SDB_ASSUME_YES)); then
        sdb_log_info "auto-confirmed (--yes): ${question}"
        return 0
    fi
    if ((SDB_NON_INTERACTIVE)); then
        sdb_die "$SDB_EX_NEEDS_DECISION" \
            "decision required but running --non-interactive: ${question}"
    fi
    if [[ ! -t 0 ]]; then
        sdb_die "$SDB_EX_NEEDS_DECISION" \
            "decision required but stdin is not a terminal: ${question}"
    fi
    printf '%s [y/N] ' "$question" >&2
    read -r reply || reply=""
    [[ $reply == [yY] || $reply == [yY][eE][sS] ]]
}

# sdb_refuse <code> <what> <why> <how-to-proceed>
# A refusal that --yes cannot override.
sdb_refuse() {
    local code=${1:?} what=${2:?} why=${3:?} how=${4:-}
    trap - ERR
    sdb_log_error "refusing: ${what}"
    sdb_log_error "reason:   ${why}"
    [[ -n $how ]] && sdb_log_error "to proceed: ${how}"
    sdb_log_event "refusal" "what=${what}" "why=${why}"
    exit "$code"
}

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

sdb_sha256() {
    local file=${1:?}
    if sdb_have sha256sum; then
        sdb_cmd sha256sum -- "$file" | { read -r sum _; printf '%s\n' "$sum"; }
    elif sdb_have shasum; then
        sdb_cmd shasum -a 256 -- "$file" | { read -r sum _; printf '%s\n' "$sum"; }
    else
        return 1
    fi
}

# sdb_json_escape <string>
sdb_json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# sdb_trim <string>
sdb_trim() {
    local s=${1-}
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

# sdb_rooted_path <system-absolute-path>
# A path written into APT configuration (a Signed-By keyring, for example) is
# absolute *on the target system*. When operating on a chroot or a fixture via
# --sys-root, the same path must be checked under that root.
sdb_rooted_path() {
    local path=${1:?}
    local root=${SDB_SYS_ROOT%/}
    if [[ -z $root || $root == "/" ]]; then
        printf '%s' "$path"
    else
        printf '%s%s' "$root" "$path"
    fi
}

# sdb_platform_fn <suffix> -> the platform hook function name for the detected
# platform. Platform ids may contain dashes ("mx-linux"); function names use
# underscores, so the mapping is normalised in exactly one place.
sdb_platform_fn() {
    local suffix=${1:?}
    printf 'sdb_platform_%s_%s' "${SDB_PLATFORM//-/_}" "$suffix"
}

# sdb_platform_call <suffix> [args...] -> call the hook if it exists.
# Returns 0 and prints nothing when the platform does not implement it.
sdb_platform_call() {
    local suffix=${1:?}; shift
    local fn
    fn=$(sdb_platform_fn "$suffix")
    declare -F "$fn" >/dev/null 2>&1 || return 0
    "$fn" "$@"
}

# sdb_in_list <needle> <haystack...>
sdb_in_list() {
    local needle=${1:?}; shift
    local item
    for item in "$@"; do
        [[ $item == "$needle" ]] && return 0
    done
    return 1
}

# sdb_file_mode <path>
sdb_file_mode() {
    sdb_cmd stat -c '%a' -- "${1:?}" 2>/dev/null || printf '%s' "?"
}

sdb_file_owner() {
    sdb_cmd stat -c '%U:%G' -- "${1:?}" 2>/dev/null || printf '%s' "?:?"
}
