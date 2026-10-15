#!/usr/bin/env bash
# rollback.sh - verified restore from a backup.
#
# Rollback is an attack surface: a forged manifest that restores files to
# arbitrary paths would be a privilege escalation. Every path is therefore
# re-validated at restore time, the platform identity in the backup must match
# the running system, and checksums must verify before anything is written.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_ROLLBACK:-} ]] && return 0
SDB_LIB_ROLLBACK=1

SDB_ROLLBACK_RESTORED=0
SDB_ROLLBACK_SKIPPED=0

# sdb_rollback_check_identity <backup-dir>
# Refuses to restore a backup taken on a different operating system.
sdb_rollback_check_identity() {
    local dir=${1:?}
    local meta="${dir}/meta.json"
    [[ -r $meta ]] || sdb_die "$SDB_EX_ROLLBACK" "backup has no meta.json: ${dir}"

    local b_platform b_os b_codename b_machine b_root
    b_platform=$(_sdb_json_get "$meta" platform || printf '')
    b_os=$(_sdb_json_get "$meta" os_id || printf '')
    b_codename=$(_sdb_json_get "$meta" codename || printf '')
    b_machine=$(_sdb_json_get "$meta" machine_id || printf '')
    b_root=$(_sdb_json_get "$meta" root || printf '')

    local now_machine
    now_machine=$(_sdb_machine_id)

    sdb_log_info "backup identity: platform=${b_platform} os=${b_os} codename=${b_codename}"
    sdb_log_info "this system:     platform=${SDB_PLATFORM} os=${SDB_OS_ID} codename=${SDB_OS_CODENAME}"

    if [[ $b_platform != "$SDB_PLATFORM" ]]; then
        sdb_refuse "$SDB_EX_ROLLBACK" \
            "restoring a backup taken on a different platform" \
            "the backup was taken on '${b_platform}' but this system is '${SDB_PLATFORM}'" \
            "restore this backup on the system it came from; --yes cannot override this"
    fi
    if [[ -n $b_os && $b_os != "$SDB_OS_ID" ]]; then
        sdb_refuse "$SDB_EX_ROLLBACK" \
            "restoring a backup from a different operating system" \
            "backup os_id='${b_os}', this system os_id='${SDB_OS_ID}'" \
            "restore this backup on the system it came from"
    fi
    if [[ -n $b_codename && -n ${SDB_OS_CODENAME:-} && $b_codename != "$SDB_OS_CODENAME" ]]; then
        sdb_log_warn "backup codename '${b_codename}' differs from this system's '${SDB_OS_CODENAME}'"
        sdb_confirm "The release has changed since this backup was taken. Restore anyway?" || \
            sdb_die "$SDB_EX_ROLLBACK" "rollback declined by operator"
    fi
    if [[ -n $b_machine && $b_machine != "unknown" && $b_machine != "$now_machine" ]]; then
        sdb_log_warn "backup was taken on a different machine-id"
        sdb_confirm "Restore a backup from another machine onto this one?" || \
            sdb_die "$SDB_EX_ROLLBACK" "rollback declined by operator"
    fi

    printf '%s' "$b_root"
}

# sdb_rollback_apply <backup-id>
sdb_rollback_apply() {
    local id=${1:?}
    local dir="${SDB_STATE_DIR:?}/backups/${id}"
    local manifest="${dir}/manifest.tsv"

    sdb_log_stage "rollback ${id}"
    SDB_ROLLBACK_RESTORED=0
    SDB_ROLLBACK_SKIPPED=0

    [[ -d $dir ]] || sdb_die "$SDB_EX_ROLLBACK" "no such backup: ${id}"
    [[ -r $manifest ]] || sdb_die "$SDB_EX_ROLLBACK" "backup has no manifest: ${manifest}"

    if ! sdb_backup_verify "$id"; then
        sdb_refuse "$SDB_EX_ROLLBACK" \
            "restoring from a backup that fails checksum verification" \
            "one or more archived files do not match the recorded SHA-256 checksums, so the backup cannot be trusted" \
            "inspect ${dir} by hand; do not restore it"
    fi

    local root
    root=$(sdb_rollback_check_identity "$dir")
    [[ -n $root ]] || sdb_die "$SDB_EX_ROLLBACK" "backup meta.json has no root path"

    local rel type mode owner group mtime link src dest
    while IFS=$'\t' read -r rel type mode owner group mtime link; do
        [[ -z $rel || $rel == '#'* ]] && continue

        # Manifest paths are untrusted: revalidate every one.
        if ! sdb_manifest_path_is_safe "$rel"; then
            sdb_log_error "refusing unsafe manifest path: ${rel}"
            SDB_ROLLBACK_SKIPPED=$((SDB_ROLLBACK_SKIPPED + 1))
            continue
        fi

        dest="${root}/${rel}"
        src="${dir}/files/${rel}"

        if ! sdb_path_is_within "$dest" "$root"; then
            sdb_log_error "refusing to restore outside the recorded root: ${dest}"
            SDB_ROLLBACK_SKIPPED=$((SDB_ROLLBACK_SKIPPED + 1))
            continue
        fi
        # And it must still be inside a write root for the detected platform.
        local ok=0 wr
        for wr in "${SDB_WRITE_ROOTS[@]:-}"; do
            sdb_path_is_within "$dest" "$wr" && { ok=1; break; }
        done
        if ((! ok)); then
            sdb_log_warn "skipping ${dest}: outside this platform's write roots"
            SDB_ROLLBACK_SKIPPED=$((SDB_ROLLBACK_SKIPPED + 1))
            continue
        fi

        if ((SDB_DRY_RUN)); then
            sdb_plan_add "restore" "$dest" "type=${type} mode=${mode} owner=${owner}:${group}"
            SDB_ROLLBACK_RESTORED=$((SDB_ROLLBACK_RESTORED + 1))
            continue
        fi

        _sdb_rollback_restore_one "$src" "$dest" "$type" "$mode" "$owner" "$group" "$mtime" "$link"
    done <"$manifest"

    _sdb_rollback_report "$id"

    if ((SDB_ROLLBACK_SKIPPED > 0)); then
        sdb_log_warn "rollback finished with ${SDB_ROLLBACK_SKIPPED} skipped entr(ies)"
    fi
    sdb_log_ok "rollback restored ${SDB_ROLLBACK_RESTORED} path(s) from backup ${id}"
    sdb_log_event "rollback" "backup=${id}" "restored=${SDB_ROLLBACK_RESTORED}" "skipped=${SDB_ROLLBACK_SKIPPED}"
    return 0
}

_sdb_rollback_restore_one() {
    local src=${1:?} dest=${2:?} type=${3:?} mode=${4:-} owner=${5:-} group=${6:-} mtime=${7:-} link=${8:-}

    sdb_assert_safe_target "$dest"
    sdb_guard_write_root "$dest"

    # If the destination is currently a symlink pointing outside our roots, do
    # not follow it - remove the link and restore the real object.
    if [[ -L $dest ]]; then
        local safe=0 wr
        for wr in "${SDB_WRITE_ROOTS[@]:-}"; do
            sdb_symlink_is_safe "$dest" "$wr" && { safe=1; break; }
        done
        if ((! safe)); then
            sdb_log_warn "destination is a symlink pointing outside the write roots; removing the link: ${dest}"
        fi
        sdb_privileged rm -f -- "$dest"
    fi

    case $type in
        dir)
            sdb_privileged_mkdir "$dest" "${mode:-0755}"
            ;;
        symlink)
            [[ -n $link && $link != "?" ]] || { sdb_log_warn "no link target recorded for ${dest}"; return 1; }
            sdb_privileged_mkdir "${dest%/*}" 0755
            sdb_privileged ln -sfn -- "$link" "$dest"
            ;;
        file)
            [[ -f $src ]] || { sdb_log_error "archived file missing: ${src}"; SDB_ROLLBACK_SKIPPED=$((SDB_ROLLBACK_SKIPPED+1)); return 1; }
            sdb_privileged_mkdir "${dest%/*}" 0755
            local tmp="${dest}.sdb-restore.$$"
            sdb_privileged install -m "${mode:-0644}" -- "$src" "$tmp"
            sdb_privileged mv -f -- "$tmp" "$dest"
            ;;
        *)
            sdb_log_warn "unknown manifest type '${type}' for ${dest}; skipped"
            SDB_ROLLBACK_SKIPPED=$((SDB_ROLLBACK_SKIPPED + 1))
            return 1
            ;;
    esac

    # Ownership: best effort, and only when we can actually set it.
    if [[ -n $owner && $owner != "?" && -n $group && $group != "?" ]]; then
        if ((SDB_IS_ROOT)) || [[ -n ${SDB_SUDO:-} ]]; then
            sdb_privileged chown --no-dereference "${owner}:${group}" -- "$dest" 2>/dev/null || \
                sdb_log_warn "could not restore ownership ${owner}:${group} on ${dest}"
        fi
    fi
    if [[ $type != "symlink" && -n $mtime && $mtime != "?" ]]; then
        sdb_privileged touch -d "@${mtime}" -- "$dest" 2>/dev/null || true
    fi

    SDB_ROLLBACK_RESTORED=$((SDB_ROLLBACK_RESTORED + 1))
    sdb_log_verbose "restored ${dest}"
    sdb_applied_add "restore" "$dest" "type=${type} from_backup=${SDB_BACKUP_ID:-}"
    return 0
}

_sdb_rollback_report() {
    local id=${1:?}
    local report="${SDB_RUN_DIR}/rollback-report.txt"
    {
        printf 'secure-debian-bootstrap rollback report\n'
        printf '=======================================\n\n'
        printf 'run id:        %s\n' "$SDB_RUN_ID"
        printf 'backup id:     %s\n' "$id"
        printf 'platform:      %s\n' "$SDB_PLATFORM"
        printf 'dry run:       %s\n' "$( ((SDB_DRY_RUN)) && echo yes || echo no)"
        printf 'restored:      %s\n' "$SDB_ROLLBACK_RESTORED"
        printf 'skipped:       %s\n' "$SDB_ROLLBACK_SKIPPED"
        printf 'completed:     %s\n' "$(date -u +%FT%TZ)"
        printf '\nThe backup was NOT removed and can be restored again:\n'
        printf '  %s\n' "${SDB_STATE_DIR}/backups/${id}"
        printf '\nNext step: verify the restored configuration with\n'
        printf '  apt-get update\n'
    } >"$report"
    sdb_log_info "rollback report: ${report}"
}
