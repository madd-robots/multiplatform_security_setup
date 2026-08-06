#!/usr/bin/env bash
# baseline-hardening.sh - conservative, reversible, platform-gated controls.
#
# Rules for every control in this file:
#   1. it is selected by the platform's hardening profile, never applied blindly
#   2. it checks for conflicts before changing anything
#   3. it is reversible, and the reversal is documented in the report
#   4. it is a no-op when already in the desired state (idempotence)
#   5. if it cannot be applied safely, it records "skipped" with a reason
#
# Controls whose correct value depends on local policy are REPORT-ONLY. This
# file makes no compliance claim (see docs/research-sources.md section 3.9).
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_HARDENING:-} ]] && return 0
SDB_LIB_HARDENING=1

declare -ga SDB_HARDENING_APPLIED=()
declare -ga SDB_HARDENING_SKIPPED=()
declare -ga SDB_HARDENING_REPORTED=()

_sdb_h_applied() {
    SDB_HARDENING_APPLIED+=("$1: $2")
    sdb_log_ok "hardening applied - $1: $2"
    sdb_log_event "hardening" "control=$1" "result=applied" "detail=$2"
}
_sdb_h_skipped() {
    SDB_HARDENING_SKIPPED+=("$1: $2")
    sdb_log_info "hardening skipped - $1: $2"
    sdb_log_event "hardening" "control=$1" "result=skipped" "detail=$2"
}
_sdb_h_reported() {
    SDB_HARDENING_REPORTED+=("$1: $2")
    sdb_log_event "hardening" "control=$1" "result=reported" "detail=$2"
}

# ---------------------------------------------------------------------------
# Report-only controls
# ---------------------------------------------------------------------------

sdb_h_package_db_check()      { sdb_package_db_check; _sdb_h_reported "package_db_check" "dpkg database audited"; }
sdb_h_keyring_check()         { sdb_keyring_inventory; _sdb_h_reported "keyring_check" "trust anchors inspected"; }

sdb_h_obsolete_metadata() {
    local lists="${SDB_SYS_ROOT%/}/var/lib/apt/lists"
    ((SDB_IS_TERMUX)) && lists="${SDB_PREFIX}/var/lib/apt/lists"
    [[ -d $lists ]] || { _sdb_h_skipped "obsolete_metadata" "no apt lists directory"; return 0; }
    local count
    count=$(sdb_cmd find "$lists" -maxdepth 1 -type f -name '*_Release' -mtime +30 2>/dev/null | wc -l)
    if ((count > 0)); then
        _sdb_h_reported "obsolete_metadata" "${count} Release file(s) older than 30 days; run 'apt-get update'"
    else
        _sdb_h_reported "obsolete_metadata" "package metadata is current"
    fi
    return 0
}

sdb_h_suid_sgid_report() {
    local -a roots=("${SDB_SYS_ROOT%/}/usr/bin" "${SDB_SYS_ROOT%/}/usr/sbin" "${SDB_SYS_ROOT%/}/bin" "${SDB_SYS_ROOT%/}/sbin")
    ((SDB_IS_TERMUX)) && roots=("${SDB_PREFIX}/bin")
    local dir f owner count=0 unowned=0
    for dir in "${roots[@]}"; do
        [[ -d $dir ]] || continue
        while IFS= read -r -d '' f; do
            count=$((count + 1))
            owner=$(_sdb_dpkg_owner "$f")
            if [[ $owner == "-" ]]; then
                unowned=$((unowned + 1))
                sdb_log_finding high "unexpected_suid" "$f" \
                    "SUID/SGID binary not owned by any installed package (mode $(sdb_file_mode "$f"))"
            fi
        done < <(sdb_cmd find "$dir" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
    done
    _sdb_h_reported "suid_sgid_report" "${count} SUID/SGID files, ${unowned} not owned by a package"
}

sdb_h_world_writable_report() {
    local -a roots=("${SDB_SYS_ROOT%/}/etc" "${SDB_SYS_ROOT%/}/usr" "${SDB_SYS_ROOT%/}/var")
    ((SDB_IS_TERMUX)) && roots=("${SDB_PREFIX}/etc" "${SDB_PREFIX}/share")
    local dir f count=0
    for dir in "${roots[@]}"; do
        [[ -d $dir ]] || continue
        while IFS= read -r -d '' f; do
            count=$((count + 1))
            sdb_log_finding medium "world_writable" "$f" "mode $(sdb_file_mode "$f")"
            ((count >= 50)) && break
        done < <(sdb_cmd find "$dir" -xdev \( -type f -o -type d \) -perm -0002 ! -type l -print0 2>/dev/null)
    done
    _sdb_h_reported "world_writable_report" "${count} world-writable path(s) reported (capped at 50)"
}

sdb_h_modified_package_files() {
    sdb_audit_modified_package_files
    _sdb_h_reported "modified_package_files" "dpkg --verify results recorded in findings"
}

sdb_h_unsafe_path_report() {
    _sdb_h_reported "unsafe_path_report" "PATH inspected during preflight; see findings"
}

sdb_h_apparmor_status_report() {
    if [[ -d "${SDB_SYS_ROOT%/}/sys/kernel/security/apparmor" ]]; then
        _sdb_h_reported "apparmor_status_report" "AppArmor is present in the kernel"
    else
        _sdb_h_reported "apparmor_status_report" "AppArmor is not active on this kernel"
    fi
    return 0
}

sdb_h_shared_storage_warning() {
    local d
    for d in "${HOME:-}/storage" "/sdcard"; do
        [[ -n $d && -d $d ]] || continue
        _sdb_h_reported "shared_storage_warning" \
            "${d} is Android shared storage: Unix ownership and permission bits are not preserved there. Never store keys, backups, or anything permission-sensitive on it."
        return 0
    done
    _sdb_h_skipped "shared_storage_warning" "no shared storage mounted"
}

# ---------------------------------------------------------------------------
# Permission controls (idempotent, reversible)
# ---------------------------------------------------------------------------

# sdb_h_file_permissions: tighten only paths this tool owns conceptually - APT
# configuration and trust anchors. It never touches user data.
sdb_h_file_permissions() {
    local -a targets=()
    local f mode changed=0

    while IFS= read -r -d '' f; do targets+=("$f"); done \
        < <(sdb_cmd find "${SDB_APT_ETC}" -maxdepth 2 -type f -print0 2>/dev/null)

    for f in "${targets[@]:-}"; do
        [[ -n $f ]] || continue
        mode=$(sdb_file_mode "$f")
        case $mode in
            *[2367])
                if ((SDB_DRY_RUN)); then
                    sdb_plan_add "chmod" "$f" "0644 (was ${mode})"
                else
                    sdb_privileged chmod 0644 -- "$f"
                    sdb_applied_add "chmod" "$f" "0644 (was ${mode})"
                fi
                changed=$((changed + 1)) ;;
        esac
    done

    if ((changed > 0)); then
        _sdb_h_applied "file_permissions" "removed group/world write from ${changed} APT configuration file(s); reverse with --rollback ${SDB_BACKUP_ID:-<backup-id>}"
    else
        _sdb_h_skipped "file_permissions" "APT configuration permissions already correct"
    fi
    return 0
}

sdb_h_git_ssh_key_permissions() {
    # REPORT ONLY. This tool never modifies key material or user data.
    local sshdir="${HOME:-}/.ssh" f mode count=0
    [[ -d $sshdir ]] || { _sdb_h_skipped "git_ssh_key_permissions" "no ~/.ssh directory"; return 0; }
    mode=$(sdb_file_mode "$sshdir")
    [[ $mode == "700" ]] || sdb_log_finding medium "ssh_dir_permissions" "$sshdir" \
        "mode ${mode}; expected 700 (not changed by this tool)"
    while IFS= read -r -d '' f; do
        case ${f##*/} in
            *.pub|known_hosts*|config|authorized_keys) continue ;;
        esac
        mode=$(sdb_file_mode "$f")
        case $mode in
            600|400) ;;
            *) count=$((count + 1))
               sdb_log_finding high "ssh_key_permissions" "$f" \
                   "private key material is mode ${mode}; expected 600. Fix by hand: chmod 600 (this tool does not modify key files)" ;;
        esac
    done < <(sdb_cmd find "$sshdir" -maxdepth 1 -type f -print0 2>/dev/null)
    _sdb_h_reported "git_ssh_key_permissions" "${count} key file(s) with unsafe permissions (reported only)"
}

# ---------------------------------------------------------------------------
# Configuration controls (drop-in files only - never edits vendor files)
# ---------------------------------------------------------------------------

# All configuration changes are written as clearly-named drop-in files, so
# reversal is "delete this one file" and nothing vendor-managed is edited.
readonly SDB_DROPIN_TAG="60-secure-debian-bootstrap"

sdb_h_ssh_client_config() {
    local dir="${SDB_SYS_ROOT%/}/etc/ssh/ssh_config.d"
    ((SDB_IS_TERMUX)) && dir="${SDB_PREFIX}/etc/ssh/ssh_config.d"
    if [[ ! -d ${dir%/*} ]]; then
        _sdb_h_skipped "ssh_client_config" "ssh is not installed"
        return 0
    fi
    if [[ ! -d $dir ]]; then
        _sdb_h_skipped "ssh_client_config" "this ssh does not support ssh_config.d drop-ins; refusing to edit ssh_config directly"
        return 0
    fi
    local target="${dir}/${SDB_DROPIN_TAG}.conf"
    local content
    content=$(cat <<'EOF'
# Written by secure-debian-bootstrap. Remove this file to revert.
# Conservative client defaults: they do not break normal Git, deployment, or
# development workflows.
Host *
    HashKnownHosts yes
    StrictHostKeyChecking ask
    ForwardAgent no
    ForwardX11 no
    ForwardX11Trusted no
    PermitLocalCommand no
EOF
)
    if [[ -f $target ]] && [[ $(cat "$target") == "$content" ]]; then
        _sdb_h_skipped "ssh_client_config" "drop-in already present and current (idempotent)"
        return 0
    fi
    if ((SDB_DRY_RUN)); then
        sdb_plan_add "write" "$target" "ssh client hardening drop-in"
        _sdb_h_reported "ssh_client_config" "[dry-run] would write ${target}"
        return 0
    fi
    sdb_require_backup
    printf '%s\n' "$content" >"${SDB_TMP_DIR}/ssh_client.conf"
    SDB_WRITE_ROOTS+=("${dir}")
    sdb_install_file "${SDB_TMP_DIR}/ssh_client.conf" "$target" 0644
    _sdb_h_applied "ssh_client_config" "wrote ${target}; revert by deleting that file"
}

sdb_h_ssh_server_config() {
    local sshd_dir="${SDB_SYS_ROOT%/}/etc/ssh/sshd_config.d"
    local sshd_main="${SDB_SYS_ROOT%/}/etc/ssh/sshd_config"
    ((SDB_IS_TERMUX)) && { sshd_dir="${SDB_PREFIX}/etc/ssh/sshd_config.d"; sshd_main="${SDB_PREFIX}/etc/ssh/sshd_config"; }

    if [[ ! -f $sshd_main ]]; then
        _sdb_h_skipped "ssh_server_config" "no sshd installed; nothing to harden"
        return 0
    fi
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$sshd_main" 2>/dev/null; then
        _sdb_h_skipped "ssh_server_config" "sshd_config has no Include for sshd_config.d; refusing to edit the vendor file directly"
        return 0
    fi
    [[ -d $sshd_dir ]] || sdb_privileged_mkdir "$sshd_dir" 0755

    # Locking yourself out is the classic sshd-hardening failure. We only set
    # options that cannot do that, and we never touch PermitRootLogin or
    # PasswordAuthentication without an explicit operator decision.
    local target="${sshd_dir}/${SDB_DROPIN_TAG}.conf"
    local content
    content=$(cat <<'EOF'
# Written by secure-debian-bootstrap. Remove this file to revert.
# Deliberately conservative: this file does NOT change PermitRootLogin or
# PasswordAuthentication, because doing so unattended can lock you out.
X11Forwarding no
AllowAgentForwarding no
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
)
    if [[ -f $target ]] && [[ $(cat "$target") == "$content" ]]; then
        _sdb_h_skipped "ssh_server_config" "drop-in already present and current (idempotent)"
        return 0
    fi
    if ((SDB_DRY_RUN)); then
        sdb_plan_add "write" "$target" "sshd hardening drop-in"
        _sdb_h_reported "ssh_server_config" "[dry-run] would write ${target}"
        return 0
    fi

    sdb_require_backup
    printf '%s\n' "$content" >"${SDB_TMP_DIR}/sshd.conf"
    SDB_WRITE_ROOTS+=("${sshd_dir}")
    sdb_install_file "${SDB_TMP_DIR}/sshd.conf" "$target" 0644

    # Validate the resulting configuration; if sshd rejects it, remove it again.
    if sdb_have sshd; then
        if ! sdb_privileged sshd -t 2>/dev/null; then
            sdb_log_error "sshd rejected the new configuration; removing the drop-in"
            sdb_privileged rm -f -- "$target"
            _sdb_h_skipped "ssh_server_config" "sshd -t failed; drop-in removed, sshd left as it was"
            return 0
        fi
    fi
    _sdb_h_applied "ssh_server_config" "wrote ${target} (validated with sshd -t); revert by deleting that file and reloading ssh"
    sdb_log_info "the running sshd was NOT reloaded; apply with: systemctl reload ssh"
}

sdb_h_core_dumps() {
    local dir="${SDB_SYS_ROOT%/}/etc/security/limits.d"
    [[ -d $dir ]] || { _sdb_h_skipped "core_dumps" "no limits.d on this system"; return 0; }
    local target="${dir}/${SDB_DROPIN_TAG}-coredump.conf"
    local content="* hard core 0"
    if [[ -f $target ]] && [[ $(cat "$target") == "$content" ]]; then
        _sdb_h_skipped "core_dumps" "already configured (idempotent)"
        return 0
    fi
    if ((SDB_DRY_RUN)); then
        sdb_plan_add "write" "$target" "disable core dumps"
        _sdb_h_reported "core_dumps" "[dry-run] would write ${target}"
        return 0
    fi
    sdb_require_backup
    printf '%s\n' "$content" >"${SDB_TMP_DIR}/coredump.conf"
    SDB_WRITE_ROOTS+=("$dir")
    sdb_install_file "${SDB_TMP_DIR}/coredump.conf" "$target" 0644
    _sdb_h_applied "core_dumps" "wrote ${target}; revert by deleting that file"
}

sdb_h_tmp_protection() {
    # Report only: changing /tmp mount options unattended can break running
    # services and, on some systems, prevent boot.
    local opts
    if opts=$(sdb_cmd findmnt -no OPTIONS /tmp 2>/dev/null) && [[ -n $opts ]]; then
        case $opts in
            *nosuid*nodev*|*nodev*nosuid*)
                _sdb_h_reported "tmp_protection" "/tmp already mounted with nosuid,nodev (${opts})" ;;
            *)
                sdb_log_finding low "tmp_mount_options" "/tmp" \
                    "mounted with '${opts}'; consider nosuid,nodev,noexec. Not changed automatically: a wrong /tmp mount can break boot."
                _sdb_h_reported "tmp_protection" "/tmp options reported, not changed" ;;
        esac
    else
        _sdb_h_skipped "tmp_protection" "/tmp is not a separate mount"
    fi
    return 0
}

sdb_h_security_updates() {
    # We never install packages unattended. We report what is pending.
    sdb_have apt-get || { _sdb_h_skipped "security_updates" "apt-get unavailable"; return 0; }
    local out count=0
    if out=$(sdb_cmd apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null); then
        count=$(grep -c '^Inst ' <<<"$out" || true)
    fi
    if ((count > 0)); then
        _sdb_h_reported "security_updates" "${count} package upgrade(s) pending. This tool does not install them; run: sudo apt-get update && sudo apt-get upgrade"
        sdb_log_finding medium "pending_updates" "system" "${count} upgradable package(s)"
    else
        _sdb_h_reported "security_updates" "no pending upgrades"
    fi
    return 0
}

sdb_h_logging() {
    local svc found=""
    for svc in rsyslog systemd-journald syslog-ng busybox-syslogd; do
        if [[ -d "${SDB_SYS_ROOT%/}/etc/${svc}" ]] || \
           [[ -f "${SDB_SYS_ROOT%/}/etc/${svc}.conf" ]] || \
           { sdb_have systemctl && sdb_cmd systemctl is-active --quiet "$svc" 2>/dev/null; }; then
            found=$svc; break
        fi
    done
    if [[ -n $found ]]; then
        _sdb_h_reported "logging" "system logging present: ${found}"
    else
        sdb_log_finding medium "no_system_logging" "system" "no system logger detected; security events may not be recorded"
        _sdb_h_reported "logging" "no system logger detected"
    fi
    return 0
}

sdb_h_auditd() {
    if [[ ${SDB_INIT:-} != "systemd" ]]; then
        _sdb_h_skipped "auditd" "requires systemd; this system uses ${SDB_INIT:-unknown}"
        return 0
    fi
    if ! sdb_have auditctl; then
        _sdb_h_reported "auditd" "auditd is not installed. This tool does not install packages; install with: sudo apt-get install auditd"
        return 0
    fi
    if sdb_have systemctl && sdb_cmd systemctl is-active --quiet auditd 2>/dev/null; then
        _sdb_h_reported "auditd" "auditd is installed and running"
    else
        _sdb_h_reported "auditd" "auditd is installed but not running; enable with: sudo systemctl enable --now auditd"
    fi
    return 0
}

sdb_h_apparmor() {
    if [[ ! -d "${SDB_SYS_ROOT%/}/sys/kernel/security/apparmor" ]]; then
        _sdb_h_skipped "apparmor" "AppArmor is not available on this kernel"
        return 0
    fi
    if sdb_have aa-status; then
        local out
        out=$(sdb_privileged aa-status --profiled 2>/dev/null || printf '0')
        _sdb_h_reported "apparmor" "AppArmor active with ${out} profile(s) loaded"
    else
        _sdb_h_reported "apparmor" "AppArmor present in the kernel but apparmor-utils is not installed"
    fi
    return 0
}

sdb_h_firewall() {
    # Report and offer, never silently enable: enabling a firewall on a remote
    # machine can disconnect the operator.
    local tool=""
    for t in ufw nft iptables firewall-cmd; do
        sdb_have "$t" && { tool=$t; break; }
    done
    if [[ -z $tool ]]; then
        _sdb_h_reported "firewall" "no firewall tool installed. Install one deliberately (ufw or nftables) - this tool will not."
        return 0
    fi
    local state="unknown"
    case $tool in
        ufw)      state=$(sdb_privileged ufw status 2>/dev/null | head -1 || printf 'unknown') ;;
        nft)      state=$(sdb_privileged nft list ruleset 2>/dev/null | head -1 || printf 'unknown') ;;
        iptables) state=$(sdb_privileged iptables -S 2>/dev/null | head -1 || printf 'unknown') ;;
    esac
    _sdb_h_reported "firewall" "${tool} present; current state: ${state:-unknown}. This tool never changes firewall rules automatically - a wrong rule can disconnect you."
    sdb_log_info "to enable a basic host firewall yourself: sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable"
}

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

sdb_hardening_run() {
    sdb_log_stage "baseline hardening"
    sdb_require_confident_platform

    local -a profile=()
    local fn
    fn=$(sdb_platform_fn hardening_profile)
    if declare -F "$fn" >/dev/null 2>&1; then
        mapfile -t profile < <("$fn")
    fi
    if ((${#profile[@]} == 0)); then
        sdb_log_warn "no hardening profile for platform ${SDB_PLATFORM}; nothing applied"
        return 0
    fi

    # Announce what this platform explicitly does not support, and why.
    local line control reason
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        control=${line%%:*}; reason=${line#*:}
        _sdb_h_skipped "$control" "unsupported on ${SDB_PLATFORM}: ${reason}"
    done < <(sdb_platform_call unsupported_controls)

    while IFS= read -r line; do
        [[ -n $line ]] || continue
        control=${line%%:*}; reason=${line#*:}
        _sdb_h_skipped "$control" "opt-in only on ${SDB_PLATFORM}: ${reason}"
    done < <(sdb_platform_call optin_controls)

    local control_fn
    for control in "${profile[@]}"; do
        [[ -n $control ]] || continue
        control_fn="sdb_h_${control}"
        if ! declare -F "$control_fn" >/dev/null 2>&1; then
            _sdb_h_skipped "$control" "not implemented"
            continue
        fi
        if ! "$control_fn"; then
            _sdb_h_skipped "$control" "control returned an error; system left unchanged by it"
        fi
    done

    sdb_log_info "hardening: ${#SDB_HARDENING_APPLIED[@]} applied, ${#SDB_HARDENING_REPORTED[@]} reported, ${#SDB_HARDENING_SKIPPED[@]} skipped"
    sdb_stage_mark "hardening"
}
