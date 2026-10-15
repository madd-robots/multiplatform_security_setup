#!/usr/bin/env bash
# quarantine.sh - copy questionable material aside, then neutralise it.
#
# Quarantine never destroys. The original is copied into the quarantine store
# first (and checksummed), and only then is the live copy disabled - by renaming
# it to a name APT ignores, not by deleting it.
#
# APT ignores files in sources.list.d that do not end in .list/.sources, and
# ignores files in apt.conf.d whose names contain characters outside
# [a-zA-Z0-9_-] (it uses the same rules as run-parts). Appending
# ".sdb-quarantined" achieves this for both, reversibly.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_QUARANTINE:-} ]] && return 0
SDB_LIB_QUARANTINE=1

readonly SDB_QUARANTINE_SUFFIX=".sdb-quarantined"
SDB_QUARANTINE_DIR=""
SDB_QUARANTINE_COUNT=0

sdb_quarantine_init() {
    SDB_QUARANTINE_DIR="${SDB_STATE_DIR:?}/quarantine/${SDB_RUN_ID}"
    ((SDB_DRY_RUN)) && return 0
    sdb_privileged_mkdir "${SDB_QUARANTINE_DIR}/files" 0700
    local m="${SDB_QUARANTINE_DIR}/manifest.tsv"
    [[ -f $m ]] || printf '#path\treason\tsha256\tquarantined_as\n' >"$m"
    return 0
}

# sdb_quarantine_file <path> <reason>
# Copies the file into quarantine and renames the original out of APT's way.
sdb_quarantine_file() {
    local path=${1:?} reason=${2:?}
    local rel dest sum disabled root

    if [[ ! -e $path && ! -L $path ]]; then
        return 0
    fi

    root=$( ((SDB_IS_TERMUX)) && printf '%s' "$SDB_PREFIX" || printf '%s' "${SDB_SYS_ROOT%/}" )
    rel=${path#"$root"/}
    [[ $rel == "$path" ]] && rel=${path#/}
    if ! sdb_manifest_path_is_safe "$rel"; then
        sdb_log_warn "refusing to quarantine an unsafe path: ${path}"
        return 1
    fi

    disabled="${path}${SDB_QUARANTINE_SUFFIX}"

    if ((SDB_DRY_RUN)); then
        sdb_plan_add "quarantine" "$path" "reason=${reason} -> ${disabled}"
        SDB_QUARANTINE_COUNT=$((SDB_QUARANTINE_COUNT + 1))
        return 0
    fi

    sdb_require_backup
    sdb_assert_safe_target "$path"
    sdb_guard_write_root "$path"

    dest="${SDB_QUARANTINE_DIR}/files/${rel}"
    sdb_privileged_mkdir "${dest%/*}" 0700
    sdb_privileged cp --no-dereference --preserve=mode,ownership,timestamps \
        -- "$path" "$dest" || {
        sdb_log_error "could not copy to quarantine, leaving original untouched: ${path}"
        return 1
    }
    sum=$(sdb_sha256 "$dest" 2>/dev/null || printf '?')

    # Only disable the live copy after the quarantine copy exists.
    if [[ -e $disabled ]]; then
        disabled="${disabled}.${SDB_RUN_ID}"
    fi
    sdb_privileged mv -n -- "$path" "$disabled" || {
        sdb_log_error "could not disable ${path}; it remains active"
        return 1
    }

    printf '%s\t%s\t%s\t%s\n' "$path" "$reason" "$sum" "$disabled" \
        >>"${SDB_QUARANTINE_DIR}/manifest.tsv"
    SDB_QUARANTINE_COUNT=$((SDB_QUARANTINE_COUNT + 1))
    sdb_log_warn "quarantined ${path} (${reason})"
    sdb_applied_add "quarantine" "$path" "reason=${reason} disabled_as=${disabled}"
    return 0
}

# sdb_quarantine_from_findings: quarantine what the audit flagged, by policy.
#
# Policy: only material that is both (a) high severity and (b) inside the APT
# configuration root is quarantined automatically. Package-managed files are
# never quarantined - a modified package file is reported so the operator can
# reinstall the package, which is the correct repair.
sdb_quarantine_from_findings() {
    local findings="${SDB_RUN_DIR}/findings.jsonl"
    [[ -r $findings ]] || return 0
    sdb_log_stage "quarantine"
    sdb_quarantine_init

    local line code target owner
    while IFS= read -r line; do
        code=$(_sdb_jsonl_field "$line" code)
        target=$(_sdb_jsonl_field "$line" target)
        [[ -n $target ]] || continue
        # Findings carry "file:line"; take the file part.
        target=${target%%:[0-9]*}
        [[ -e $target ]] || continue

        case $code in
            apt_hook|apt_verification_disabled|apt_conf_executable|apt_dir_override|\
            repo_trusted_yes|repo_cross_distribution|repo_development_suite|repo_proposed_suite)
                ;;
            *) continue ;;
        esac

        # Never quarantine a file owned by an installed package.
        owner=$(_sdb_dpkg_owner "$target")
        if [[ $owner != "-" ]]; then
            sdb_log_warn "not quarantining package-owned file ${target} (owned by ${owner}); reinstall the package instead"
            continue
        fi
        if ! sdb_path_is_within "$target" "${SDB_APT_ETC}"; then
            sdb_log_warn "not quarantining ${target}: outside the APT configuration root"
            continue
        fi
        sdb_quarantine_file "$target" "$code"
    done <"$findings"

    if ((SDB_QUARANTINE_COUNT > 0)); then
        sdb_log_info "quarantined ${SDB_QUARANTINE_COUNT} item(s) -> ${SDB_QUARANTINE_DIR}"
    else
        sdb_log_ok "nothing required quarantine"
    fi
    sdb_stage_mark "quarantine"
}

# sdb_quarantine_third_party: disable-and-preserve non-vendor repositories.
# Third-party repositories are NOT destroyed; they are disabled so the baseline
# repair happens against vendor archives only, and the operator can re-enable
# them deliberately afterwards.
sdb_quarantine_third_party() {
    local path
    while IFS= read -r path; do
        [[ -n $path && -f $path ]] || continue
        sdb_quarantine_file "$path" "third_party_repository_disabled_for_baseline_repair"
    done < <(sdb_inventory_select "third-party")
}

# _sdb_jsonl_field <json-line> <key> - flat string fields only.
_sdb_jsonl_field() {
    local line=${1:?} key=${2:?} rest
    rest=${line#*"\"${key}\":\""}
    [[ $rest == "$line" ]] && return 1
    printf '%s' "${rest%%\"*}"
}

# sdb_quarantine_restore <run-id> - undo a quarantine (operator-invoked).
sdb_quarantine_restore() {
    local runid=${1:?}
    local m="${SDB_STATE_DIR:?}/quarantine/${runid}/manifest.tsv"
    [[ -r $m ]] || sdb_die "$SDB_EX_FAIL" "no quarantine manifest for run ${runid}"
    local path reason sum disabled
    while IFS=$'\t' read -r path reason sum disabled; do
        [[ $path == '#'* || -z $path ]] && continue
        [[ -e $disabled ]] || { sdb_log_warn "missing quarantined file: ${disabled}"; continue; }
        sdb_assert_safe_target "$path"
        sdb_guard_write_root "$path"
        if ((SDB_DRY_RUN)); then
            sdb_plan_add "unquarantine" "$path" "from ${disabled}"
            continue
        fi
        sdb_privileged mv -n -- "$disabled" "$path"
        sdb_log_ok "restored ${path}"
    done <"$m"
}
