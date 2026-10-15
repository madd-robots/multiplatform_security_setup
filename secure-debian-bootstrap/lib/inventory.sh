#!/usr/bin/env bash
# inventory.sh - enumerate and classify every APT configuration file.
#
# Classification vocabulary (docs/repository-recovery.md):
#   distro-repo    a repository file this platform's vendor ships
#   third-party    a repository file for a non-vendor archive
#   pkg-managed    owned by an installed package (dpkg -S resolves it)
#   admin          unowned but in an expected location with expected content
#   suspicious     unowned and matching an audit pattern, or in an odd location
#   keyring        a trust anchor
#   unknown        present but unclassifiable
#
# Nothing here executes, sources, or evaluates any file it reads.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_INVENTORY:-} ]] && return 0
SDB_LIB_INVENTORY=1

SDB_INVENTORY_FILE=""
declare -ga SDB_INVENTORY_PATHS=()

# sdb_inventory_paths: the set of locations this platform cares about.
sdb_inventory_target_paths() {
    local etc=${SDB_APT_ETC:?}
    local -a paths=(
        "${etc}/sources.list"
        "${etc}/sources.list.d"
        "${etc}/apt.conf"
        "${etc}/apt.conf.d"
        "${etc}/preferences"
        "${etc}/preferences.d"
        "${etc}/trusted.gpg"
        "${etc}/trusted.gpg.d"
        "${etc}/keyrings"
        "${etc}/auth.conf"
        "${etc}/auth.conf.d"
    )
    if ! ((SDB_IS_TERMUX)); then
        paths+=("${SDB_SYS_ROOT%/}/usr/share/keyrings")
    else
        paths+=("${SDB_PREFIX}/share/termux-keyring")
    fi
    printf '%s\n' "${paths[@]}"
}

# _sdb_dpkg_owner <path> -> package name or "-"
_sdb_dpkg_owner() {
    local path=${1:?} out
    sdb_have dpkg-query || { printf '%s' "-"; return 0; }
    if out=$(sdb_cmd dpkg-query -S -- "$path" 2>/dev/null); then
        printf '%s' "${out%%:*}"
    else
        printf '%s' "-"
    fi
    return 0
}

# _sdb_classify <path> -> classification token
_sdb_classify() {
    local path=${1:?} owner=${2:-"-"}
    local base=${path##*/}

    case $path in
        */trusted.gpg.d/*|*/keyrings/*|*/termux-keyring/*|*/trusted.gpg)
            printf '%s' "keyring"; return 0 ;;
    esac

    if [[ $owner != "-" ]]; then
        case $base in
            *.list|*.sources) printf '%s' "distro-repo"; return 0 ;;
            *) printf '%s' "pkg-managed"; return 0 ;;
        esac
    fi

    case $base in
        *.list|*.sources)
            # Unowned repository definitions: vendor-named files are treated as
            # distro-repo candidates (a vendor file can legitimately be unowned
            # after `apt modernize-sources`), everything else is third-party
            # until the audit says otherwise.
            case $base in
                sources.list|debian.sources|ubuntu.sources|kali.sources|parrot.list|mx.list|debian.list|debian-stable-updates.list)
                    printf '%s' "distro-repo" ;;
                *) printf '%s' "third-party" ;;
            esac
            return 0
            ;;
        *.list.bak|*.save|*.distUpgrade|*.dpkg-*|*.ucf-*)
            printf '%s' "admin"; return 0 ;;
    esac

    case $path in
        */apt.conf.d/*|*/apt.conf|*/preferences|*/preferences.d/*)
            printf '%s' "admin"; return 0 ;;
    esac

    printf '%s' "unknown"
}

# sdb_inventory_run: writes inventory.tsv and populates SDB_INVENTORY_PATHS.
# Columns: path, type, class, owner, mode, ownergroup, size, link-target, sha256
sdb_inventory_run() {
    sdb_log_stage "inventory"
    SDB_INVENTORY_FILE="${SDB_RUN_DIR}/inventory.tsv"
    SDB_INVENTORY_PATHS=()
    : >"$SDB_INVENTORY_FILE"
    printf '#path\ttype\tclass\towner\tmode\townergroup\tsize\tlink_target\tsha256\n' \
        >>"$SDB_INVENTORY_FILE"

    local target
    while IFS= read -r target; do
        [[ -e $target || -L $target ]] || continue
        if [[ -d $target && ! -L $target ]]; then
            _sdb_inventory_dir "$target"
        else
            _sdb_inventory_one "$target"
        fi
    done < <(sdb_inventory_target_paths)

    local count
    count=$(( $(wc -l <"$SDB_INVENTORY_FILE") - 1 ))
    sdb_log_ok "inventoried ${count} paths -> ${SDB_INVENTORY_FILE}"
    sdb_log_event "inventory" "count=${count}" "file=${SDB_INVENTORY_FILE}"
}

_sdb_inventory_dir() {
    local dir=${1:?} entry
    # -print0 with read -d '' : no ls parsing, no word splitting, no -exec sh.
    while IFS= read -r -d '' entry; do
        _sdb_inventory_one "$entry"
    done < <(sdb_cmd find "$dir" -mindepth 1 -maxdepth 1 \
                \( -type f -o -type l -o -type d \) -print0 2>/dev/null)
    _sdb_inventory_one "$dir"
}

_sdb_inventory_one() {
    local path=${1:?} type class owner mode ownergroup size link sum

    if [[ -L $path ]]; then
        type="symlink"
        link=$(sdb_cmd readlink -- "$path" 2>/dev/null || printf '?')
        sum="-"
        size="-"
    elif [[ -d $path ]]; then
        type="dir"; link="-"; sum="-"; size="-"
    elif [[ -f $path ]]; then
        type="file"; link="-"
        size=$(sdb_cmd stat -c '%s' -- "$path" 2>/dev/null || printf '?')
        sum=$(sdb_sha256 "$path" 2>/dev/null || printf '?')
    else
        type="other"; link="-"; sum="-"; size="-"
    fi

    mode=$(sdb_file_mode "$path")
    ownergroup=$(sdb_file_owner "$path")
    owner=$(_sdb_dpkg_owner "$path")
    class=$(_sdb_classify "$path" "$owner")

    SDB_INVENTORY_PATHS+=("$path")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$path" "$type" "$class" "$owner" "$mode" "$ownergroup" "$size" "$link" "$sum" \
        >>"$SDB_INVENTORY_FILE"
}

# sdb_inventory_select <class> -> paths of that class, one per line
sdb_inventory_select() {
    local want=${1:?} path type class rest
    [[ -r ${SDB_INVENTORY_FILE:-} ]] || return 0
    while IFS=$'\t' read -r path type class rest; do
        [[ $path == '#'* ]] && continue
        [[ $class == "$want" ]] && printf '%s\n' "$path"
    done <"$SDB_INVENTORY_FILE"
    return 0
}

# sdb_inventory_summary: human-readable counts by class.
sdb_inventory_summary() {
    [[ -r ${SDB_INVENTORY_FILE:-} ]] || return 0
    local path type class rest
    declare -A counts=()
    while IFS=$'\t' read -r path type class rest; do
        [[ $path == '#'* ]] && continue
        counts[$class]=$(( ${counts[$class]:-0} + 1 ))
    done <"$SDB_INVENTORY_FILE"
    local key
    for key in "${!counts[@]}"; do
        printf '  %-14s %s\n' "$key" "${counts[$key]}"
    done | sort
}
