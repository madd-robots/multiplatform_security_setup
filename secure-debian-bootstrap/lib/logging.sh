#!/usr/bin/env bash
# logging.sh - human-readable log, JSONL event log, and redaction.
#
# Logs stay on the machine. Nothing here transmits, uploads, or phones home.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_LOGGING:-} ]] && return 0
SDB_LIB_LOGGING=1

SDB_LOG_FILE=""
SDB_EVENT_FILE=""
SDB_LOG_STARTED=0

# Colour only when stderr is a terminal and NO_COLOR is unset.
if [[ -t 2 && -z ${NO_COLOR:-} ]]; then
    SDB_C_RESET=$'\033[0m'; SDB_C_RED=$'\033[31m'; SDB_C_YEL=$'\033[33m'
    SDB_C_BLU=$'\033[34m';  SDB_C_GRN=$'\033[32m'; SDB_C_DIM=$'\033[2m'
else
    SDB_C_RESET=""; SDB_C_RED=""; SDB_C_YEL=""; SDB_C_BLU=""; SDB_C_GRN=""; SDB_C_DIM=""
fi

# ---------------------------------------------------------------------------
# Redaction
#
# Applied to every line before it reaches a file or the terminal. Patterns
# cover proxy credentials in URLs, common token shapes, Authorization headers,
# and PEM private key bodies (which must never be copied into a log at all -
# the tool never reads key material, but a quoted config line might contain
# one).
# ---------------------------------------------------------------------------
sdb_redact() {
    local line=${1-}
    # scheme://user:password@host -> scheme://user:REDACTED@host
    line=$(printf '%s' "$line" | sed -E \
        -e 's#((https?|ftp|socks[45]?)://[^:/@[:space:]]+):[^@[:space:]]+@#\1:REDACTED@#g' \
        -e 's#(Acquire::[A-Za-z:]*[Pp]roxy[^=]*=[[:space:]]*"?[^:"]+://[^:"]+):[^@"]+@#\1:REDACTED@#g' \
        -e 's#([Aa]uthorization:[[:space:]]*[A-Za-z]+[[:space:]]+)[A-Za-z0-9._~+/=-]+#\1REDACTED#g' \
        -e 's#(([Pp]ass(word)?|[Ss]ecret|[Tt]oken|[Aa]pi[_-]?[Kk]ey)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+#\1REDACTED#g' \
        -e 's#-----BEGIN [A-Z ]*PRIVATE KEY-----.*#-----BEGIN PRIVATE KEY----- REDACTED#g' \
        -e 's#(gh[pousr]_)[A-Za-z0-9]{10,}#\1REDACTED#g' )
    printf '%s' "$line"
}

# sdb_log_init <run-dir>
sdb_log_init() {
    local dir=${1:?}
    SDB_LOG_FILE="${dir}/run.log"
    SDB_EVENT_FILE="${dir}/events.jsonl"
    : >"$SDB_LOG_FILE"
    : >"$SDB_EVENT_FILE"
    chmod 0600 -- "$SDB_LOG_FILE" "$SDB_EVENT_FILE" 2>/dev/null || true
    SDB_LOG_STARTED=1
    sdb_log_event "run_start" "run_id=${SDB_RUN_ID}" "mode=${SDB_MODE}" \
        "dry_run=${SDB_DRY_RUN}" "version=${SDB_VERSION:-unknown}"
}

# _sdb_log <level> <colour> <message...>
_sdb_log() {
    local level=$1 colour=$2; shift 2
    local msg ts
    msg=$(sdb_redact "$*")
    ts=$(date -u +%FT%TZ)
    printf '%s%-5s%s %s\n' "$colour" "$level" "$SDB_C_RESET" "$msg" >&2
    if ((SDB_LOG_STARTED)) && [[ -n $SDB_LOG_FILE ]]; then
        printf '%s [%s] %s\n' "$ts" "$level" "$msg" >>"$SDB_LOG_FILE"
    fi
    return 0
}

sdb_log_error() { _sdb_log "ERROR" "$SDB_C_RED" "$@"; }
sdb_log_warn()  { _sdb_log "WARN"  "$SDB_C_YEL" "$@"; }
sdb_log_info()  { _sdb_log "INFO"  "$SDB_C_BLU" "$@"; }
sdb_log_ok()    { _sdb_log "OK"    "$SDB_C_GRN" "$@"; }
sdb_log_debug() {
    ((SDB_DEBUG)) || return 0
    _sdb_log "DEBUG" "$SDB_C_DIM" "$@"
}
sdb_log_verbose() {
    ((SDB_VERBOSE || SDB_DEBUG)) || return 0
    _sdb_log "INFO" "$SDB_C_DIM" "$@"
}

# sdb_log_stage <name>
sdb_log_stage() {
    local name=${1:?}
    printf '\n%s== %s ==%s\n' "$SDB_C_BLU" "$name" "$SDB_C_RESET" >&2
    if ((SDB_LOG_STARTED)) && [[ -n $SDB_LOG_FILE ]]; then
        printf '\n=== stage: %s ===\n' "$name" >>"$SDB_LOG_FILE"
    fi
    sdb_log_event "stage" "name=${name}"
}

# sdb_log_event <type> [key=value ...]
# Writes one JSON object per line. Keys and values are escaped; values are
# redacted first.
sdb_log_event() {
    local type=${1:?}; shift
    ((SDB_LOG_STARTED)) || return 0
    [[ -n $SDB_EVENT_FILE ]] || return 0
    local out kv key value
    out=$(printf '{"ts":"%s","run_id":"%s","type":"%s"' \
        "$(date -u +%FT%TZ)" "$(sdb_json_escape "${SDB_RUN_ID:-}")" \
        "$(sdb_json_escape "$type")")
    for kv in "$@"; do
        key=${kv%%=*}
        value=${kv#*=}
        [[ $kv == *=* ]] || { key=$kv; value=""; }
        value=$(sdb_redact "$value")
        out+=$(printf ',"%s":"%s"' "$(sdb_json_escape "$key")" "$(sdb_json_escape "$value")")
    done
    out+='}'
    printf '%s\n' "$out" >>"$SDB_EVENT_FILE"
}

# sdb_log_finding <severity> <code> <target> <detail>
# Findings are both logged and appended to findings.jsonl for reporting.
sdb_log_finding() {
    local severity=${1:?} code=${2:?} target=${3:-} detail=${4:-}
    local colour=$SDB_C_YEL
    case $severity in
        high)   colour=$SDB_C_RED ;;
        medium) colour=$SDB_C_YEL ;;
        low|info) colour=$SDB_C_DIM ;;
    esac
    _sdb_log "FIND" "$colour" "[${severity}] ${code}: ${target} ${detail}"
    if [[ -n ${SDB_RUN_DIR:-} && -d ${SDB_RUN_DIR:-} ]]; then
        printf '{"ts":"%s","severity":"%s","code":"%s","target":"%s","detail":"%s"}\n' \
            "$(date -u +%FT%TZ)" \
            "$(sdb_json_escape "$severity")" \
            "$(sdb_json_escape "$code")" \
            "$(sdb_json_escape "$(sdb_redact "$target")")" \
            "$(sdb_json_escape "$(sdb_redact "$detail")")" \
            >>"${SDB_RUN_DIR}/findings.jsonl"
    fi
    case $severity in
        high)   SDB_FINDINGS_HIGH=$((${SDB_FINDINGS_HIGH:-0} + 1)) ;;
        medium) SDB_FINDINGS_MEDIUM=$((${SDB_FINDINGS_MEDIUM:-0} + 1)) ;;
        *)      SDB_FINDINGS_LOW=$((${SDB_FINDINGS_LOW:-0} + 1)) ;;
    esac
    return 0
}

SDB_FINDINGS_HIGH=0
SDB_FINDINGS_MEDIUM=0
SDB_FINDINGS_LOW=0
