#!/usr/bin/env bash
# backup.sh - timestamped, verified backup of APT configuration.
#
# Rules:
#   - never overwrite an existing backup
#   - never delete a backup (this project contains no retention/pruning code)
#   - preserve ownership, mode, timestamps, symlinks, and xattrs where supported
#   - produce a SHA-256 manifest and verify it before the backup is usable
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_BACKUP:-} ]] && return 0
SDB_LIB_BACKUP=1

SDB_BACKUP_ID=""
SDB_BACKUP_DIR=""

# sdb_backup_create: back up every inventoried path. Sets SDB_BACKUP_ID.
sdb_backup_create() {
    sdb_log_stage "backup"
    local base="${SDB_STATE_DIR:?}/backups"
    SDB_BACKUP_ID="${SDB_RUN_ID}"
    SDB_BACKUP_DIR="${base}/${SDB_BACKUP_ID}"

    if [[ -e $SDB_BACKUP_DIR ]]; then
        sdb_die "$SDB_EX_BACKUP" "backup directory already exists, refusing to overwrite: ${SDB_BACKUP_DIR}"
    fi

    if ((SDB_DRY_RUN)); then
        sdb_plan_add "backup" "$SDB_BACKUP_DIR" "archive APT configuration from ${SDB_APT_ETC}"
        sdb_log_info "[dry-run] would create backup ${SDB_BACKUP_ID}"
        return 0
    fi

    sdb_privileged_mkdir "${SDB_BACKUP_DIR}/files" 0700
    local manifest="${SDB_BACKUP_DIR}/manifest.tsv"
    local sums="${SDB_BACKUP_DIR}/manifest.sha256"
    : >"$manifest"; : >"$sums"
    printf '#relpath\ttype\tmode\towner\tgroup\tmtime\tlink_target\n' >>"$manifest"

    local root count=0 target
    root=$(_sdb_backup_root)

    while IFS= read -r target; do
        [[ -e $target || -L $target ]] || continue
        if [[ -d $target && ! -L $target ]]; then
            while IFS= read -r -d '' entry; do
                _sdb_backup_one "$entry" "$root" "$manifest" "$sums" && count=$((count + 1))
            done < <(sdb_cmd find "$target" -mindepth 0 \( -type f -o -type l -o -type d \) -print0 2>/dev/null)
        else
            _sdb_backup_one "$target" "$root" "$manifest" "$sums" && count=$((count + 1))
        fi
    done < <(sdb_inventory_target_paths)

    _sdb_backup_meta

    if ! sdb_backup_verify "$SDB_BACKUP_ID"; then
        sdb_die "$SDB_EX_BACKUP" "backup verification failed immediately after creation: ${SDB_BACKUP_ID}"
    fi

    sdb_log_ok "backup ${SDB_BACKUP_ID} created and verified (${count} paths)"
    sdb_log_event "backup" "id=${SDB_BACKUP_ID}" "dir=${SDB_BACKUP_DIR}" "count=${count}"
    sdb_applied_add "backup" "$SDB_BACKUP_DIR" "paths=${count}"
    sdb_stage_mark "backup"
}

# The archive is stored relative to a single root so restore can validate that
# every manifest path stays inside it.
_sdb_backup_root() {
    if ((SDB_IS_TERMUX)); then
        printf '%s' "${SDB_PREFIX}"
    else
        printf '%s' "${SDB_SYS_ROOT%/}"
    fi
    return 0
}

# _sdb_backup_one <path> <root> <manifest> <sums>
_sdb_backup_one() {
    local path=${1:?} root=${2:?} manifest=${3:?} sums=${4:?}
    local rel dest mode owner group mtime link type

    rel=${path#"$root"/}
    [[ $rel == "$path" ]] && rel=${path#/}
    sdb_manifest_path_is_safe "$rel" || {
        sdb_log_warn "skipping unsafe path during backup: ${path}"
        return 1
    }

    dest="${SDB_BACKUP_DIR}/files/${rel}"
    mode=$(sdb_cmd stat -c '%a' -- "$path" 2>/dev/null || printf '')
    owner=$(sdb_cmd stat -c '%U' -- "$path" 2>/dev/null || printf '')
    group=$(sdb_cmd stat -c '%G' -- "$path" 2>/dev/null || printf '')
    mtime=$(sdb_cmd stat -c '%Y' -- "$path" 2>/dev/null || printf '')
    link="-"

    if [[ -L $path ]]; then
        type="symlink"
        link=$(sdb_cmd readlink -- "$path" 2>/dev/null || printf '?')
        sdb_privileged_mkdir "${dest%/*}" 0700
        # Archive the link itself, never its target.
        sdb_cmd ln -sfn -- "$link" "$dest" 2>/dev/null || {
            sdb_log_warn "could not archive symlink: ${path}"
            return 1
        }
    elif [[ -d $path ]]; then
        type="dir"
        sdb_privileged_mkdir "$dest" "${mode:-0755}"
    elif [[ -f $path ]]; then
        type="file"
        sdb_privileged_mkdir "${dest%/*}" 0700
        # --no-dereference and --preserve: a symlink swapped in underneath us is
        # copied as a link, not followed.
        sdb_privileged cp --no-dereference --preserve=mode,ownership,timestamps \
            -- "$path" "$dest" 2>/dev/null || {
            sdb_log_warn "could not archive file: ${path}"
            return 1
        }
        local sum
        if sum=$(sdb_sha256 "$dest" 2>/dev/null); then
            printf '%s  files/%s\n' "$sum" "$rel" >>"$sums"
        fi
        _sdb_backup_xattrs "$path" "$rel"
    else
        return 1
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$rel" "$type" "${mode:-?}" "${owner:-?}" "${group:-?}" "${mtime:-?}" "$link" \
        >>"$manifest"
    return 0
}

# Extended attributes and ACLs are recorded as data, restored best-effort.
_sdb_backup_xattrs() {
    local path=${1:?} rel=${2:?}
    if sdb_have getfattr; then
        local dump
        if dump=$(sdb_cmd getfattr -d -m - -- "$path" 2>/dev/null) && [[ -n $dump ]]; then
            printf '# %s\n%s\n' "$rel" "$dump" >>"${SDB_BACKUP_DIR}/xattrs.txt"
        fi
    fi
    if sdb_have getfacl; then
        local acl
        if acl=$(sdb_cmd getfacl -p -- "$path" 2>/dev/null) && [[ -n $acl ]]; then
            printf '# %s\n%s\n' "$rel" "$acl" >>"${SDB_BACKUP_DIR}/acls.txt"
        fi
    fi
    return 0
}

# Backup identity: rollback refuses to restore into a different OS.
_sdb_backup_meta() {
    local meta="${SDB_BACKUP_DIR}/meta.json"
    {
        printf '{\n'
        printf '  "backup_id": "%s",\n' "$(sdb_json_escape "$SDB_BACKUP_ID")"
        printf '  "run_id": "%s",\n' "$(sdb_json_escape "$SDB_RUN_ID")"
        printf '  "created": "%s",\n' "$(date -u +%FT%TZ)"
        printf '  "tool_version": "%s",\n' "$(sdb_json_escape "${SDB_VERSION:-unknown}")"
        printf '  "platform": "%s",\n' "$(sdb_json_escape "$SDB_PLATFORM")"
        printf '  "os_id": "%s",\n' "$(sdb_json_escape "$SDB_OS_ID")"
        printf '  "version_id": "%s",\n' "$(sdb_json_escape "$SDB_OS_VERSION_ID")"
        printf '  "codename": "%s",\n' "$(sdb_json_escape "$SDB_OS_CODENAME")"
        printf '  "arch": "%s",\n' "$(sdb_json_escape "$SDB_ARCH")"
        printf '  "machine_id": "%s",\n' "$(sdb_json_escape "$(_sdb_machine_id)")"
        printf '  "root": "%s",\n' "$(sdb_json_escape "$(_sdb_backup_root)")"
        printf '  "apt_etc": "%s"\n' "$(sdb_json_escape "$SDB_APT_ETC")"
        printf '}\n'
    } >"$meta"
    chmod 0600 -- "$meta" 2>/dev/null || true
}

_sdb_machine_id() {
    local f="${SDB_SYS_ROOT%/}/etc/machine-id"
    if [[ -r $f ]]; then
        local id; read -r id <"$f" 2>/dev/null || id=""
        printf '%s' "${id:-unknown}"
    else
        printf '%s' "unknown"
    fi
    return 0
}

# sdb_backup_verify <backup-id> -> 0 if every checksum matches
sdb_backup_verify() {
    local id=${1:?}
    local dir="${SDB_STATE_DIR:?}/backups/${id}"
    local sums="${dir}/manifest.sha256"

    if [[ ! -d $dir ]]; then
        sdb_log_error "no such backup: ${id}"
        return 1
    fi
    if [[ ! -r "${dir}/meta.json" ]]; then
        sdb_log_error "backup ${id} has no meta.json; refusing to trust it"
        return 1
    fi
    if [[ ! -r $sums ]]; then
        sdb_log_error "backup ${id} has no checksum manifest"
        return 1
    fi
    if [[ ! -s $sums ]]; then
        # A backup of a system with no regular files is possible but notable.
        sdb_log_warn "backup ${id} contains no checksummed files"
        return 0
    fi
    if sdb_have sha256sum; then
        if ( cd -- "$dir" && sdb_cmd sha256sum --quiet --check "$sums" ) >/dev/null 2>&1; then
            sdb_log_verbose "backup ${id} checksums verified"
            return 0
        fi
        sdb_log_error "backup ${id} FAILED checksum verification"
        local report=""
        if ! report=$( cd -- "$dir" && sdb_cmd sha256sum --check "$sums" 2>&1 ); then
            : # a non-zero status here is expected; the detail is in $report
        fi
        while IFS= read -r bad; do
            [[ -n $bad && $bad != *': OK' ]] && sdb_log_error "  ${bad}"
        done <<<"$report"
        return 1
    fi
    sdb_log_warn "sha256sum unavailable; cannot verify backup ${id}"
    return 1
}

# sdb_require_backup: called at the top of every modifying stage.
sdb_require_backup() {
    if ((SDB_DRY_RUN)); then
        return 0
    fi
    if [[ -z ${SDB_BACKUP_ID:-} ]]; then
        sdb_refuse "$SDB_EX_BACKUP" \
            "modifying the system without a backup" \
            "no backup has been taken in this run" \
            "run --backup-only first, or use a mode that includes the backup stage"
    fi
    if ! sdb_backup_verify "$SDB_BACKUP_ID"; then
        sdb_refuse "$SDB_EX_BACKUP" \
            "modifying the system with an unverifiable backup" \
            "backup ${SDB_BACKUP_ID} failed checksum verification" \
            "investigate the backup directory before making any change"
    fi
    return 0
}

# sdb_backup_list: available backups, newest last.
sdb_backup_list() {
    local base="${SDB_STATE_DIR:?}/backups" d id
    [[ -d $base ]] || { printf 'no backups in %s\n' "$base"; return 0; }
    while IFS= read -r d; do
        id=${d##*/}
        printf '%s' "$id"
        if [[ -r "${d}/meta.json" ]]; then
            local platform codename
            platform=$(_sdb_json_get "${d}/meta.json" platform)
            codename=$(_sdb_json_get "${d}/meta.json" codename)
            printf '  platform=%s codename=%s' "${platform:-?}" "${codename:-?}"
        fi
        printf '\n'
    done < <(sdb_cmd find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
}

# _sdb_json_get <file> <key> - flat string values only; no JSON parser required.
_sdb_json_get() {
    local file=${1:?} key=${2:?} line
    [[ -r $file ]] || return 1
    while IFS= read -r line; do
        line=$(sdb_trim "$line")
        case $line in
            "\"${key}\":"*)
                line=${line#*:}
                line=$(sdb_trim "$line")
                line=${line%,}
                line=${line#\"}
                line=${line%\"}
                printf '%s' "$line"
                return 0 ;;
        esac
    done <"$file"
    return 1
}
