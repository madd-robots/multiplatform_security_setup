#!/usr/bin/env bash
# package-trust.sh - keyring inventory, ownership, fingerprints, expiry.
#
# This module never adds, fetches, or imports a key. Trust anchors come from
# distribution keyring packages only. apt-key is never used (deprecated and
# removed); its presence on the system is itself reported.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_PKG_TRUST:-} ]] && return 0
SDB_LIB_PKG_TRUST=1

# sdb_keyring_inventory: list every trust anchor with ownership and permissions.
sdb_keyring_inventory() {
    local dir f owner mode ownergroup count=0
    sdb_log_stage "package trust"
    for dir in "${SDB_KEYRING_DIRS[@]:-}"; do
        [[ -n $dir && -d $dir ]] || continue
        while IFS= read -r -d '' f; do
            count=$((count + 1))
            owner=$(_sdb_dpkg_owner "$f")
            mode=$(sdb_file_mode "$f")
            ownergroup=$(sdb_file_owner "$f")

            if [[ -L $f ]]; then
                # Termux ships keyring symlinks by design; elsewhere a symlinked
                # trust anchor deserves scrutiny.
                local allowed=0 allow
                while IFS= read -r allow; do
                    [[ -n $allow ]] || continue
                    sdb_symlink_is_safe "$f" "$allow" && allowed=1
                done < <(sdb_platform_call symlink_allowlist)
                if ((allowed)); then
                    sdb_log_verbose "keyring symlink (expected): ${f}"
                else
                    sdb_log_finding medium "keyring_symlink" "$f" \
                        "trust anchor is a symlink to $(sdb_cmd readlink -- "$f" 2>/dev/null || printf '?')"
                fi
            fi

            if [[ $owner == "-" ]]; then
                sdb_log_finding high "keyring_unowned" "$f" \
                    "trust anchor is not owned by any installed package (mode=${mode} owner=${ownergroup})"
            else
                sdb_log_verbose "keyring ${f} owned by ${owner} (mode=${mode})"
            fi

            case $mode in
                *[2367]) sdb_log_finding high "keyring_writable" "$f" \
                    "trust anchor is group/world-writable (mode=${mode})" ;;
            esac

            case $ownergroup in
                root:*|*:root) ;;
                *) ((SDB_IS_TERMUX)) || sdb_log_finding high "keyring_owner" "$f" \
                    "trust anchor is not owned by root (${ownergroup})" ;;
            esac
        done < <(sdb_cmd find "$dir" -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
    done
    sdb_log_info "inspected ${count} trust anchor(s)"

    # The legacy monolithic keyring: not fatal, but it bypasses per-source
    # Signed-By scoping and should be migrated away from.
    local legacy="${SDB_APT_ETC}/trusted.gpg"
    if [[ -f $legacy && -s $legacy ]]; then
        sdb_log_finding medium "legacy_trusted_gpg" "$legacy" \
            "keys here are trusted for every repository; migrate them to per-source Signed-By keyrings"
    fi

    if sdb_have apt-key; then
        sdb_log_finding low "apt_key_present" "${SDB_CMD[apt-key]}" \
            "apt-key is deprecated; this tool never uses it and neither should new configuration"
    fi
    return 0
}

# sdb_key_expiry_report: report expired or soon-to-expire signing keys.
sdb_key_expiry_report() {
    sdb_have gpg || { sdb_log_warn "gpg unavailable; key expiry could not be checked"; return 0; }
    local dir f line now soon
    now=$(date -u +%s)
    soon=$(( now + 30 * 24 * 3600 ))

    for dir in "${SDB_KEYRING_DIRS[@]:-}"; do
        [[ -n $dir && -d $dir ]] || continue
        while IFS= read -r -d '' f; do
            case ${f##*/} in
                *.gpg|*.asc|*.kbx) ;;
                *) continue ;;
            esac
            while IFS= read -r line; do
                # colon-delimited: pub:validity:...:creation:expiry:...
                [[ $line == pub:* ]] || continue
                local -a fields=()
                IFS=':' read -r -a fields <<<"$line"
                local validity=${fields[1]:-} expiry=${fields[6]:-}
                case $validity in
                    e) sdb_log_finding high "key_expired" "$f" "a signing key in this keyring has expired" ;;
                    r) sdb_log_finding high "key_revoked" "$f" "a signing key in this keyring is revoked" ;;
                esac
                if [[ $expiry =~ ^[0-9]+$ ]]; then
                    if (( expiry > now && expiry < soon )); then
                        sdb_log_finding medium "key_expiring_soon" "$f" \
                            "a signing key expires on $(date -u -d "@${expiry}" +%F 2>/dev/null || printf '%s' "$expiry")"
                    fi
                fi
            done < <(sdb_cmd gpg --no-default-keyring --batch --quiet \
                        --with-colons --show-keys -- "$f" 2>/dev/null || true)
        done < <(sdb_cmd find "$dir" -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
    done
    return 0
}

# sdb_package_db_check: is the dpkg database itself sane?
sdb_package_db_check() {
    sdb_have dpkg || { sdb_log_warn "dpkg unavailable; package database not checked"; return 0; }
    local out
    if ! out=$(sdb_cmd dpkg --audit 2>&1); then
        sdb_log_finding medium "dpkg_audit_failed" "dpkg" "dpkg --audit exited non-zero"
    fi
    if [[ -n $(sdb_trim "$out") ]]; then
        sdb_log_finding medium "dpkg_broken_packages" "dpkg" \
            "dpkg --audit reports packages in an inconsistent state; resolve before repairing repositories"
        local line
        while IFS= read -r line; do
            [[ -n $(sdb_trim "$line") ]] && sdb_log_verbose "  ${line}"
        done <<<"$out"
    else
        sdb_log_ok "dpkg database is consistent"
    fi
    return 0
}

sdb_package_trust_run() {
    sdb_keyring_inventory
    sdb_key_expiry_report
    sdb_package_db_check
    sdb_stage_mark "package-trust"
}
