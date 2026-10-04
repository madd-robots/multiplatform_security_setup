#!/usr/bin/env bash
# reporting.sh - final human and machine-readable summaries.
#
# Reports are written to the run directory and printed. They are never
# transmitted anywhere.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_REPORTING:-} ]] && return 0
SDB_LIB_REPORTING=1

sdb_report_text() {
    local out="${SDB_RUN_DIR}/report.txt"
    {
        printf 'secure-debian-bootstrap report\n'
        printf '=============================\n\n'
        printf 'run id:      %s\n' "$SDB_RUN_ID"
        printf 'mode:        %s\n' "$SDB_MODE"
        printf 'dry run:     %s\n' "$( ((SDB_DRY_RUN)) && echo yes || echo no)"
        printf 'started:     %s\n' "${SDB_RUN_STARTED:-unknown}"
        printf 'finished:    %s\n' "$(date -u +%FT%TZ)"
        printf 'tool:        %s\n\n' "${SDB_VERSION:-unknown}"

        printf -- '-- detection --\n'
        sdb_detection_report
        printf '\n'

        if [[ -r ${SDB_INVENTORY_FILE:-} ]]; then
            printf -- '-- inventory --\n'
            sdb_inventory_summary
            printf '  full inventory: %s\n\n' "$SDB_INVENTORY_FILE"
        fi

        printf -- '-- findings --\n'
        printf '  high:   %s\n' "$SDB_FINDINGS_HIGH"
        printf '  medium: %s\n' "$SDB_FINDINGS_MEDIUM"
        printf '  low:    %s\n' "$SDB_FINDINGS_LOW"
        if [[ -r "${SDB_RUN_DIR}/findings.jsonl" ]]; then
            printf '\n'
            local line severity code target detail
            while IFS= read -r line; do
                severity=$(_sdb_jsonl_field "$line" severity)
                code=$(_sdb_jsonl_field "$line" code)
                target=$(_sdb_jsonl_field "$line" target)
                detail=$(_sdb_jsonl_field "$line" detail)
                printf '  [%-6s] %-28s %s\n' "$severity" "$code" "$target"
                [[ -n $detail ]] && printf '             %s\n' "$detail"
            done <"${SDB_RUN_DIR}/findings.jsonl"
        fi
        printf '\n'

        printf -- '-- release --\n'
        printf '  status: %s\n' "${SDB_RELEASE_STATUS:-unknown}"
        [[ -n ${SDB_RELEASE_EOL_DATE:-} ]] && printf '  eol:    %s\n' "$SDB_RELEASE_EOL_DATE"
        printf '\n'

        if ((${#SDB_PLAN[@]} > 0)); then
            printf -- '-- planned changes --\n'
            local entry action target detail
            for entry in "${SDB_PLAN[@]}"; do
                [[ -n $entry ]] || continue
                IFS=$'\t' read -r action target detail <<<"$entry"
                printf '  %-12s %s\n' "$action" "$target"
                [[ -n $detail ]] && printf '               %s\n' "$detail"
            done
            printf '\n'
        fi

        if ((${#SDB_APPLIED[@]} > 0)); then
            printf -- '-- applied changes --\n'
            local entry action target detail
            for entry in "${SDB_APPLIED[@]}"; do
                [[ -n $entry ]] || continue
                IFS=$'\t' read -r action target detail <<<"$entry"
                printf '  %-12s %s\n' "$action" "$target"
            done
            printf '\n'
        fi

        if ((${#SDB_HARDENING_APPLIED[@]} + ${#SDB_HARDENING_REPORTED[@]} + ${#SDB_HARDENING_SKIPPED[@]} > 0)); then
            printf -- '-- hardening --\n'
            local h
            for h in "${SDB_HARDENING_APPLIED[@]:-}"; do [[ -n $h ]] && printf '  applied  %s\n' "$h"; done
            for h in "${SDB_HARDENING_REPORTED[@]:-}"; do [[ -n $h ]] && printf '  reported %s\n' "$h"; done
            for h in "${SDB_HARDENING_SKIPPED[@]:-}"; do [[ -n $h ]] && printf '  skipped  %s\n' "$h"; done
            printf '\n'
        fi

        printf -- '-- artifacts --\n'
        printf '  run directory: %s\n' "$SDB_RUN_DIR"
        printf '  log:           %s\n' "${SDB_LOG_FILE:-none}"
        printf '  events:        %s\n' "${SDB_EVENT_FILE:-none}"
        [[ -n ${SDB_BACKUP_DIR:-} ]] && printf '  backup:        %s\n' "$SDB_BACKUP_DIR"
        [[ -n ${SDB_QUARANTINE_DIR:-} && -d ${SDB_QUARANTINE_DIR:-} ]] && \
            printf '  quarantine:    %s\n' "$SDB_QUARANTINE_DIR"
        [[ -d ${SDB_STAGING_DIR:-} ]] && printf '  staging:       %s\n' "$SDB_STAGING_DIR"
        printf '\n'

        printf -- '-- how to undo this run --\n'
        if [[ -n ${SDB_BACKUP_ID:-} ]]; then
            printf '  %s --rollback %s\n' "${SDB_SELF:-secure-debian-bootstrap}" "$SDB_BACKUP_ID"
            printf '  (preview first with: %s --rollback %s --dry-run)\n' \
                "${SDB_SELF:-secure-debian-bootstrap}" "$SDB_BACKUP_ID"
        else
            printf '  no backup was taken (no modifying stage ran)\n'
        fi
        if [[ -n ${SDB_QUARANTINE_DIR:-} && -d ${SDB_QUARANTINE_DIR:-} ]]; then
            printf '  quarantined files were preserved; each was renamed with the suffix %s\n' "$SDB_QUARANTINE_SUFFIX"
        fi
        printf '\n'

        if [[ ${SDB_TEMPLATE_CONFIDENCE:-} == "secondary" ]]; then
            printf -- '-- operator decisions still outstanding --\n'
            printf '  The repository template used for %s is SECONDARY confidence.\n' "$SDB_PLATFORM"
            printf '  Verify templates/%s/ against the vendor documentation.\n\n' "$SDB_PLATFORM"
        fi
    } >"$out"
    chmod 0600 -- "$out" 2>/dev/null || true
    printf '%s' "$out"
}

sdb_report_json() {
    local out="${SDB_RUN_DIR}/report.json"
    {
        printf '{\n'
        printf '  "run_id": "%s",\n' "$(sdb_json_escape "$SDB_RUN_ID")"
        printf '  "tool_version": "%s",\n' "$(sdb_json_escape "${SDB_VERSION:-unknown}")"
        printf '  "mode": "%s",\n' "$(sdb_json_escape "$SDB_MODE")"
        printf '  "dry_run": %s,\n' "$( ((SDB_DRY_RUN)) && echo true || echo false)"
        printf '  "platform": "%s",\n' "$(sdb_json_escape "$SDB_PLATFORM")"
        printf '  "codename": "%s",\n' "$(sdb_json_escape "${SDB_OS_CODENAME:-}")"
        printf '  "confidence": %s,\n' "${SDB_CONFIDENCE:-0}"
        printf '  "release_status": "%s",\n' "$(sdb_json_escape "${SDB_RELEASE_STATUS:-unknown}")"
        printf '  "template_confidence": "%s",\n' "$(sdb_json_escape "${SDB_TEMPLATE_CONFIDENCE:-none}")"
        printf '  "findings": {"high": %s, "medium": %s, "low": %s},\n' \
            "$SDB_FINDINGS_HIGH" "$SDB_FINDINGS_MEDIUM" "$SDB_FINDINGS_LOW"
        printf '  "backup_id": "%s",\n' "$(sdb_json_escape "${SDB_BACKUP_ID:-}")"
        printf '  "planned_changes": %s,\n' "${#SDB_PLAN[@]}"
        printf '  "applied_changes": %s,\n' "${#SDB_APPLIED[@]}"
        printf '  "quarantined": %s,\n' "${SDB_QUARANTINE_COUNT:-0}"
        printf '  "run_dir": "%s"\n' "$(sdb_json_escape "$SDB_RUN_DIR")"
        printf '}\n'
    } >"$out"
    chmod 0600 -- "$out" 2>/dev/null || true
    printf '%s' "$out"
}

sdb_report_run() {
    sdb_plan_flush
    sdb_applied_flush
    local txt json
    txt=$(sdb_report_text)
    json=$(sdb_report_json)
    sdb_log_stage "report"
    cat "$txt"
    sdb_log_info "report:      ${txt}"
    sdb_log_info "report json: ${json}"
    sdb_log_event "run_end" "findings_high=${SDB_FINDINGS_HIGH}" "applied=${#SDB_APPLIED[@]}"
}
