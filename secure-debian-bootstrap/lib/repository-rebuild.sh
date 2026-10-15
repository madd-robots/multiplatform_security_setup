#!/usr/bin/env bash
# repository-rebuild.sh - render templates into a staging tree.
#
# This module never writes into the live APT configuration. It produces a
# complete miniature APT root under $SDB_RUN_DIR/staging, which
# repository-validate.sh then tests before anything is activated.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_REPO_REBUILD:-} ]] && return 0
SDB_LIB_REPO_REBUILD=1

declare -ga SDB_STAGED_FILES=()    # "staged-path<TAB>live-destination"
SDB_TEMPLATE_DIR=""
SDB_TEMPLATE_CONFIDENCE=""

# sdb_template_meta_get <platform> <key>
sdb_template_meta_get() {
    local platform=${1:?} key=${2:?} meta line
    meta="${SDB_ROOT_DIR:?}/templates/${platform}/TEMPLATE.meta"
    [[ -r $meta ]] || return 1
    local out=""
    while IFS= read -r line || [[ -n $line ]]; do
        line=$(sdb_trim "$line")
        [[ -z $line || $line == '#'* ]] && continue
        [[ ${line%%=*} == "$key" ]] || continue
        if [[ -n $out ]]; then out+=" ${line#*=}"; else out=${line#*=}; fi
    done <"$meta"
    [[ -n $out ]] || return 1
    printf '%s' "$out"
}

# sdb_check_template_confidence: enforce the fail-closed rule for templates
# whose repository facts were not verified against a vendor-primary source.
sdb_check_template_confidence() {
    local platform=${1:?}
    SDB_TEMPLATE_CONFIDENCE=$(sdb_template_meta_get "$platform" confidence 2>/dev/null || printf 'unknown')
    case $SDB_TEMPLATE_CONFIDENCE in
        primary)
            sdb_log_ok "template confidence: primary (verified against a vendor source)"
            return 0 ;;
        secondary)
            if ((SDB_ALLOW_SECONDARY_TEMPLATE)); then
                sdb_log_warn "template confidence is SECONDARY and --allow-secondary-template was given"
                sdb_log_warn "source: $(sdb_template_meta_get "$platform" source 2>/dev/null || printf 'unrecorded')"
                sdb_log_warn "verify templates/${platform}/ against the vendor before trusting this system"
                return 0
            fi
            sdb_refuse "$SDB_EX_VALIDATE" \
                "activating a secondary-confidence repository template for ${platform}" \
                "this build could not read ${platform}'s repository definitions from the vendor (see docs/research-sources.md); the template is structurally plausible but unverified, and writing an unverified archive URI is exactly the failure this tool exists to prevent" \
                "review templates/${platform}/ against the vendor documentation, then re-run with --allow-secondary-template" ;;
        *)
            sdb_refuse "$SDB_EX_VALIDATE" \
                "activating a repository template with no recorded provenance" \
                "templates/${platform}/TEMPLATE.meta has no usable 'confidence' field" \
                "add provenance metadata to the template before using it" ;;
    esac
    return 0
}

# _sdb_render <template-file> <output-file> <var=value ...>
# Substitution is literal @NAME@ -> value, performed with parameter expansion.
# No eval, no envsubst, no sed with untrusted replacement text.
_sdb_render() {
    local src=${1:?} dst=${2:?}; shift 2
    local line out kv name value
    [[ -r $src ]] || sdb_die "$SDB_EX_FAIL" "template not readable: ${src}"
    : >"$dst"
    while IFS= read -r line || [[ -n $line ]]; do
        out=$line
        for kv in "$@"; do
            name=${kv%%=*}
            value=${kv#*=}
            out=${out//@${name}@/${value}}
        done
        printf '%s\n' "$out" >>"$dst"
    done <"$src"
    # An unsubstituted placeholder means a template/platform mismatch: refuse.
    if grep -q '@[A-Z_]\+@' "$dst" 2>/dev/null; then
        sdb_die "$SDB_EX_FAIL" \
            "template ${src##*/} still contains unsubstituted placeholders: $(grep -o '@[A-Z_]\+@' "$dst" | sort -u | tr '\n' ' ')"
    fi
    return 0
}

# sdb_uri_is_official <uri>: every URI written must belong to a host the
# platform module declares official. This is what prevents a repair from
# pointing APT anywhere unexpected.
sdb_uri_is_official() {
    local uri=${1:?} host pattern
    local -a official=()
    local fn
    fn=$(sdb_platform_fn official_hosts)
    if declare -F "$fn" >/dev/null 2>&1; then
        mapfile -t official < <("$fn")
    fi
    ((${#official[@]})) || return 1
    host=${uri#*://}
    host=${host%%/*}
    host=${host%%:*}
    for pattern in "${official[@]}"; do
        [[ -n $pattern ]] || continue
        [[ $host == "$pattern" ]] && return 0
    done
    return 1
}

# _sdb_verify_rendered <file>: structural checks on generated content, before
# it goes anywhere near apt.
_sdb_verify_rendered() {
    local file=${1:?} line lineno=0 uri
    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$((lineno + 1))
        line=$(sdb_trim "$line")
        [[ -z $line || $line == '#'* ]] && continue

        # Absolute prohibitions, regardless of platform or flags.
        case ${line,,} in
            *trusted=yes*|*trusted=true*|*"trusted: yes"*|*"trusted: true"*)
                sdb_die "$SDB_EX_VALIDATE" \
                    "generated configuration would disable signature verification (${file}:${lineno}); this is a bug in the template" ;;
            *allowinsecurerepositories*|*allowunauthenticated*)
                sdb_die "$SDB_EX_VALIDATE" \
                    "generated configuration would allow unauthenticated packages (${file}:${lineno})" ;;
        esac

        uri=""
        if [[ $line == deb* ]]; then
            # legacy: deb [opts] uri suite comps
            local rest=$line
            [[ $rest == *'['*']'* ]] && rest="${rest%%[*}${rest#*]}"
            # shellcheck disable=SC2086
            set -- $rest
            uri=${2:-}
        elif [[ ${line,,} == uris:* ]]; then
            uri=$(sdb_trim "${line#*:}")
        fi

        local u
        for u in $uri; do
            [[ -n $u ]] || continue
            if ! sdb_uri_is_official "$u"; then
                sdb_die "$SDB_EX_VALIDATE" \
                    "generated configuration references a host that is not official for ${SDB_PLATFORM}: ${u} (${file}:${lineno})"
            fi
        done

        # Signed-By must point at a keyring that exists.
        if [[ ${line,,} == signed-by:* ]]; then
            local keyring
            keyring=$(sdb_trim "${line#*:}")
            if [[ ! -f $(sdb_rooted_path "$keyring") ]]; then
                sdb_die "$SDB_EX_VALIDATE" \
                    "generated configuration references a missing keyring: ${keyring} (${file}:${lineno}); install the distribution's archive keyring package first"
            fi
        fi
    done <"$file"
    return 0
}

# sdb_rebuild_run: render every template this platform needs into staging.
sdb_rebuild_run() {
    sdb_log_stage "rebuild (staging only - the live configuration is untouched)"
    sdb_require_confident_platform
    sdb_require_supported_release
    sdb_check_template_confidence "$SDB_PLATFORM"

    SDB_TEMPLATE_DIR="${SDB_ROOT_DIR:?}/templates/${SDB_PLATFORM}"
    [[ -d $SDB_TEMPLATE_DIR ]] || sdb_die "$SDB_EX_FAIL" "no templates for platform ${SDB_PLATFORM}"

    # Build the staging APT root skeleton.
    local stage="${SDB_STAGING_DIR}/etc/apt"
    mkdir -p -- "${stage}/sources.list.d" "${stage}/apt.conf.d" \
        "${stage}/preferences.d" "${SDB_STAGING_DIR}/var/lib/apt/lists/partial"
    chmod 0755 -- "${stage}" "${stage}/sources.list.d" "${stage}/apt.conf.d" \
        "${stage}/preferences.d" 2>/dev/null || true

    # Establish platform state (suite, components, mirror) in this shell before
    # capturing render_vars, which runs in a subshell.
    sdb_platform_call prepare

    # Template variables from the platform module.
    local -a vars=()
    local fn
    fn=$(sdb_platform_fn render_vars)
    if declare -F "$fn" >/dev/null 2>&1; then
        mapfile -t vars < <("$fn")
    fi

    # Which templates, and where they will eventually live.
    local -a selections=()
    fn=$(sdb_platform_fn select_template)
    declare -F "$fn" >/dev/null 2>&1 || \
        sdb_die "$SDB_EX_FAIL" "platform module for ${SDB_PLATFORM} does not implement ${fn}"
    mapfile -t selections < <("$fn")

    SDB_STAGED_FILES=()
    local sel tmpl dest staged relpath
    for sel in "${selections[@]}"; do
        [[ -n $sel ]] || continue
        IFS=$'\t' read -r tmpl dest <<<"$sel"

        # The eventual destination must be inside this platform's write roots.
        sdb_assert_safe_target "$dest"
        sdb_guard_write_root "$dest"

        relpath=${dest#"${SDB_APT_ETC}"/}
        staged="${stage}/${relpath}"
        mkdir -p -- "${staged%/*}"
        chmod 0755 -- "${staged%/*}" 2>/dev/null || true
        _sdb_render "${SDB_TEMPLATE_DIR}/${tmpl}" "$staged" "${vars[@]:-}"
        _sdb_verify_rendered "$staged"
        chmod 0644 -- "$staged"

        SDB_STAGED_FILES+=("${staged}"$'\t'"${dest}")
        sdb_plan_add "write" "$dest" "from template ${SDB_PLATFORM}/${tmpl}"
        sdb_log_info "staged ${dest}"
        sdb_log_verbose "  content:"
        if ((SDB_VERBOSE || SDB_DEBUG || SDB_DRY_RUN)); then
            while IFS= read -r line; do
                [[ -n $(sdb_trim "$line") && $line != '#'* ]] && sdb_log_verbose "    ${line}"
            done <"$staged"
        fi
    done

    # Preserve the existing sources.list when we are replacing it with a
    # sources.list.d file: it must be emptied of active entries, not deleted.
    _sdb_stage_legacy_neutralisation "$stage"

    sdb_log_ok "staged ${#SDB_STAGED_FILES[@]} file(s) in ${SDB_STAGING_DIR}"
    sdb_stage_mark "rebuild"
}

# When the platform's canonical layout is deb822 in sources.list.d, a leftover
# legacy sources.list would duplicate every entry. We stage a commented-out
# replacement rather than removing the file.
_sdb_stage_legacy_neutralisation() {
    local stage=${1:?}
    local live_list="${SDB_APT_ETC}/sources.list"
    local writing_deb822=0 entry staged dest
    for entry in "${SDB_STAGED_FILES[@]:-}"; do
        [[ -n $entry ]] || continue
        IFS=$'\t' read -r staged dest <<<"$entry"
        [[ $dest == *".sources" ]] && writing_deb822=1
    done
    ((writing_deb822)) || return 0
    [[ -f $live_list ]] || return 0
    # Does it still contain active entries?
    grep -qE '^[[:space:]]*deb' "$live_list" 2>/dev/null || return 0

    local staged_list="${stage}/sources.list"
    {
        printf '# Neutralised by secure-debian-bootstrap run %s.\n' "$SDB_RUN_ID"
        printf '# This system uses deb822 sources in sources.list.d; the entries below were\n'
        printf '# commented out to avoid duplicate definitions. The original file is in the\n'
        printf '# backup for this run and can be restored with --rollback %s.\n' "$SDB_BACKUP_ID"
        local line
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ $(sdb_trim "$line") == deb* ]]; then
                printf '#%s\n' "$line"
            else
                printf '%s\n' "$line"
            fi
        done <"$live_list"
    } >"$staged_list"
    chmod 0644 -- "$staged_list"
    SDB_STAGED_FILES+=("${staged_list}"$'\t'"${live_list}")
    sdb_plan_add "neutralise" "$live_list" "comment out legacy entries superseded by deb822"
}

# sdb_activate_run: atomically move validated staged files into place.
# Called only after repository-validate.sh has succeeded.
sdb_activate_run() {
    sdb_log_stage "activate"
    sdb_require_backup

    ((${#SDB_STAGED_FILES[@]})) || {
        sdb_log_warn "nothing staged; nothing to activate"
        return 0
    }

    if ((SDB_DRY_RUN)); then
        local entry staged dest
        for entry in "${SDB_STAGED_FILES[@]}"; do
            IFS=$'\t' read -r staged dest <<<"$entry"
            sdb_log_info "[dry-run] would install ${dest}"
        done
        return 0
    fi

    local entry staged dest activated=0 rollback_needed=0
    for entry in "${SDB_STAGED_FILES[@]}"; do
        IFS=$'\t' read -r staged dest <<<"$entry"
        if ! sdb_install_file "$staged" "$dest" 0644; then
            rollback_needed=1
            break
        fi
        activated=$((activated + 1))
    done

    if ((rollback_needed)); then
        sdb_log_error "activation failed after ${activated} file(s); restoring from backup ${SDB_BACKUP_ID}"
        sdb_rollback_apply "$SDB_BACKUP_ID"
        sdb_die "$SDB_EX_VALIDATE" "activation aborted and the original configuration was restored"
    fi

    sdb_log_ok "activated ${activated} file(s)"
    sdb_stage_mark "activate"
}
