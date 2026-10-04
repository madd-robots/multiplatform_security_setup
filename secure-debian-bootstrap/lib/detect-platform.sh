#!/usr/bin/env bash
# detect-platform.sh - evidence-based platform detection.
#
# Detection never depends on a single variable. Each piece of evidence adds to
# a confidence score and is recorded verbatim, so a human can see exactly why
# the tool concluded what it concluded. Below SDB_MIN_CONFIDENCE, or when two
# distributions both claim the system, every modifying stage refuses to run -
# including under --yes.
#
# All reads are rooted at SDB_SYS_ROOT (default "/") so the whole detector can
# be pointed at a test fixture.
# shellcheck shell=bash
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused/unassigned to it. This
# is the project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153

[[ -n ${SDB_LIB_DETECT:-} ]] && return 0
SDB_LIB_DETECT=1

# Results
SDB_PLATFORM=""            # termux|debian|ubuntu|kali|parrot|mx-linux|generic-debian|unknown
SDB_FAMILY=""              # debian|termux|unknown
SDB_OS_ID=""
SDB_OS_ID_LIKE=""
SDB_OS_NAME=""
SDB_OS_VERSION_ID=""
SDB_OS_CODENAME=""
SDB_OS_PRETTY=""
SDB_VARIANT=""             # e.g. "purple" for Kali Purple
SDB_ARCH=""
SDB_FOREIGN_ARCHES=""
SDB_INIT=""                # systemd|sysvinit|openrc|runit|android|unknown
SDB_IS_TERMUX=0
SDB_HAS_APT=0
SDB_PKG_MANAGER=""
SDB_CONFIDENCE=0
SDB_DETECT_AMBIGUOUS=0
declare -ga SDB_EVIDENCE=()
declare -ga SDB_DETECT_CANDIDATES=()

_sdb_evidence() {
    SDB_EVIDENCE+=("$1")
    sdb_log_debug "evidence: $1"
}

_sdb_score() {
    local points=$1 why=$2
    SDB_CONFIDENCE=$((SDB_CONFIDENCE + points))
    _sdb_evidence "+${points} ${why}"
}

# ---------------------------------------------------------------------------
# os-release parsing
#
# os-release is shell-syntax, but we do NOT source it: it is untrusted input on
# a possibly-compromised system (threat model T1). It is parsed line-wise and
# only known keys are accepted.
# ---------------------------------------------------------------------------
_sdb_parse_os_release() {
    local file=${1:?} line key value
    [[ -r $file ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        line=$(sdb_trim "$line")
        [[ -z $line || $line == '#'* ]] && continue
        [[ $line == *=* ]] || continue
        key=${line%%=*}
        value=${line#*=}
        # Strip one layer of matching quotes; never expand.
        if [[ $value == \"*\" || $value == \'*\' ]]; then
            value=${value:1:${#value}-2}
        fi
        # Reject anything that looks like an attempt at substitution. The
        # single quotes are intentional: these are literal characters to match.
        # shellcheck disable=SC2016
        [[ $value == *'$('* || $value == *'`'* ]] && continue
        case $key in
            ID)              SDB_OS_ID=$value ;;
            ID_LIKE)         SDB_OS_ID_LIKE=$value ;;
            NAME)            SDB_OS_NAME=$value ;;
            VERSION_ID)      SDB_OS_VERSION_ID=$value ;;
            VERSION_CODENAME) SDB_OS_CODENAME=$value ;;
            PRETTY_NAME)     SDB_OS_PRETTY=$value ;;
            DEBIAN_CODENAME) [[ -z $SDB_OS_CODENAME ]] && SDB_OS_CODENAME=$value ;;
            VARIANT_ID)      SDB_VARIANT=$value ;;
        esac
    done <"$file"
    return 0
}

# ---------------------------------------------------------------------------
# Termux
#
# Termux is detected from several independent signals because a plain Debian
# chroot on Android can look Android-ish, and Termux itself may be missing
# TERMUX_VERSION when invoked from cron or an ssh session.
# ---------------------------------------------------------------------------
_sdb_detect_termux() {
    local hits=0
    if [[ -n ${TERMUX_VERSION:-} ]]; then
        hits=$((hits + 1)); _sdb_evidence "TERMUX_VERSION=${TERMUX_VERSION}"
    fi
    if [[ -n ${PREFIX:-} && ${PREFIX} == *"/com.termux/files/usr" ]]; then
        hits=$((hits + 1)); _sdb_evidence "PREFIX=${PREFIX}"
    fi
    if [[ -d "${SDB_SYS_ROOT%/}/data/data/com.termux/files/usr" ]]; then
        hits=$((hits + 1)); _sdb_evidence "/data/data/com.termux/files/usr exists"
    fi
    if [[ -n ${ANDROID_ROOT:-} || -n ${ANDROID_DATA:-} ]]; then
        hits=$((hits + 1)); _sdb_evidence "ANDROID_ROOT/ANDROID_DATA set"
    fi
    if [[ -x "${PREFIX:-/nonexistent}/bin/pkg" ]]; then
        hits=$((hits + 1)); _sdb_evidence "termux pkg present at \$PREFIX/bin/pkg"
    fi
    if [[ $(uname -o 2>/dev/null || printf '%s' unknown) == "Android" ]]; then
        hits=$((hits + 1)); _sdb_evidence "uname -o = Android"
    fi
    (( hits >= 2 ))
}

# ---------------------------------------------------------------------------
# Init system
# ---------------------------------------------------------------------------
sdb_detect_init() {
    local root=${SDB_SYS_ROOT%/}
    if ((SDB_IS_TERMUX)); then
        SDB_INIT="android"
        _sdb_evidence "init=android (Termux: no init access)"
        return 0
    fi
    if [[ -d "${root}/run/systemd/system" ]]; then
        SDB_INIT="systemd"
    elif [[ -L "${root}/sbin/init" ]] && \
         [[ $(sdb_cmd readlink -- "${root}/sbin/init" 2>/dev/null) == *systemd* ]]; then
        SDB_INIT="systemd"
    elif [[ -x "${root}/lib/sysvinit/init" || -d "${root}/etc/rc.d" ]] || \
         { [[ -d "${root}/etc/init.d" ]] && [[ ! -d "${root}/run/systemd/system" ]] && \
           [[ -f "${root}/etc/inittab" ]]; }; then
        SDB_INIT="sysvinit"
    elif [[ -d "${root}/run/openrc" || -x "${root}/sbin/openrc" ]]; then
        SDB_INIT="openrc"
    elif [[ -d "${root}/etc/runit" ]]; then
        SDB_INIT="runit"
    else
        SDB_INIT="unknown"
    fi
    _sdb_evidence "init=${SDB_INIT}"
}

# ---------------------------------------------------------------------------
# Distribution-specific corroboration
#
# Each check looks for evidence the distribution itself installs, independent
# of os-release, so a forged os-release alone cannot steer the tool.
# ---------------------------------------------------------------------------
_sdb_corroborate() {
    local root=${SDB_SYS_ROOT%/}

    # Kali
    if [[ -f "${root}/etc/os-release" ]] && [[ $SDB_OS_ID == "kali" ]]; then
        SDB_DETECT_CANDIDATES+=("kali")
        _sdb_score 40 "os-release ID=kali"
    fi
    [[ -f "${root}/usr/share/keyrings/kali-archive-keyring.gpg" ]] && \
        { SDB_DETECT_CANDIDATES+=("kali"); _sdb_score 25 "kali-archive-keyring.gpg present"; }
    [[ -f "${root}/etc/apt/sources.list.d/kali.sources" ]] && \
        _sdb_score 10 "kali.sources present"

    # Parrot
    if [[ $SDB_OS_ID == "parrot" || $SDB_OS_ID == "Parrot" ]]; then
        SDB_DETECT_CANDIDATES+=("parrot")
        _sdb_score 40 "os-release ID=parrot"
    fi
    [[ -f "${root}/etc/apt/sources.list.d/parrot.list" ]] && \
        { SDB_DETECT_CANDIDATES+=("parrot"); _sdb_score 25 "parrot.list present"; }
    [[ -d "${root}/usr/share/parrot-menu" || -f "${root}/etc/parrot_version" ]] && \
        _sdb_score 10 "parrot system files present"

    # MX Linux: os-release ID is "mx" (some builds report debian with
    # NAME="MX"), so the MX-specific files matter more here than elsewhere.
    if [[ $SDB_OS_ID == "mx" ]]; then
        SDB_DETECT_CANDIDATES+=("mx-linux")
        _sdb_score 40 "os-release ID=mx"
    fi
    [[ -f "${root}/etc/mx-version" ]] && \
        { SDB_DETECT_CANDIDATES+=("mx-linux"); _sdb_score 30 "/etc/mx-version present"; }
    [[ -f "${root}/etc/apt/sources.list.d/mx.list" ]] && \
        { SDB_DETECT_CANDIDATES+=("mx-linux"); _sdb_score 20 "mx.list present"; }
    [[ -d "${root}/usr/share/mx-packageinstaller" || -x "${root}/usr/bin/mx-repo-manager" ]] && \
        _sdb_score 10 "MX tools present"

    # Ubuntu
    if [[ $SDB_OS_ID == "ubuntu" ]]; then
        SDB_DETECT_CANDIDATES+=("ubuntu")
        _sdb_score 40 "os-release ID=ubuntu"
    fi
    [[ -f "${root}/usr/share/keyrings/ubuntu-archive-keyring.gpg" ]] && \
        { SDB_DETECT_CANDIDATES+=("ubuntu"); _sdb_score 30 "ubuntu-archive-keyring.gpg present"; }
    [[ -f "${root}/etc/lsb-release" ]] && \
        grep -qs 'DISTRIB_ID=Ubuntu' "${root}/etc/lsb-release" && \
        _sdb_score 10 "lsb-release DISTRIB_ID=Ubuntu"

    # Debian - checked last because every derivative above also looks Debian-ish
    if [[ $SDB_OS_ID == "debian" ]]; then
        SDB_DETECT_CANDIDATES+=("debian")
        _sdb_score 40 "os-release ID=debian"
    fi
    [[ -f "${root}/etc/debian_version" ]] && \
        _sdb_score 15 "/etc/debian_version present"
    [[ -f "${root}/usr/share/keyrings/debian-archive-keyring.gpg" ]] && \
        _sdb_score 20 "debian-archive-keyring.gpg present"
    # Explicit: this function is called as a statement, and a trailing failed
    # test must not abort the run under set -e.
    return 0
}

# ---------------------------------------------------------------------------
# Package tooling
# ---------------------------------------------------------------------------
_sdb_detect_package_tools() {
    local root=${SDB_SYS_ROOT%/}
    if sdb_have apt-get; then
        SDB_HAS_APT=1
        SDB_PKG_MANAGER=${SDB_CMD[apt-get]}
        _sdb_evidence "apt-get=${SDB_CMD[apt-get]}"
    elif [[ -x "${root}/usr/bin/apt-get" ]]; then
        SDB_HAS_APT=1
        SDB_PKG_MANAGER="${root}/usr/bin/apt-get"
        _sdb_evidence "apt-get=${root}/usr/bin/apt-get (not on PATH)"
    fi
    sdb_have dpkg && _sdb_evidence "dpkg=${SDB_CMD[dpkg]}"
    if sdb_have dpkg; then
        SDB_ARCH=$(sdb_cmd dpkg --print-architecture 2>/dev/null || printf '')
        SDB_FOREIGN_ARCHES=$(sdb_cmd dpkg --print-foreign-architectures 2>/dev/null | tr '\n' ' ')
    fi
    [[ -z $SDB_ARCH ]] && SDB_ARCH=$(uname -m 2>/dev/null || printf 'unknown')
    _sdb_evidence "arch=${SDB_ARCH} foreign='${SDB_FOREIGN_ARCHES}'"
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
sdb_detect_platform() {
    : "${SDB_SYS_ROOT:=/}"
    local root=${SDB_SYS_ROOT%/}
    SDB_EVIDENCE=()
    SDB_DETECT_CANDIDATES=()
    SDB_CONFIDENCE=0

    sdb_resolve_cmd readlink stat uname date sed grep >/dev/null 2>&1 || true

    # 1. Termux first: it is not a Debian installation and must never be
    #    classified as one.
    if _sdb_detect_termux; then
        SDB_IS_TERMUX=1
        SDB_PLATFORM="termux"
        SDB_FAMILY="termux"
        SDB_PREFIX=${PREFIX:-"${root}/data/data/com.termux/files/usr"}
        SDB_CONFIDENCE=95
        _sdb_evidence "classified as Termux on >=2 independent signals"
    fi

    # 2. os-release (both standard locations)
    local osr
    for osr in "${root}/etc/os-release" "${root}/usr/lib/os-release"; do
        if [[ -r $osr ]]; then
            _sdb_parse_os_release "$osr"
            _sdb_evidence "read ${osr}"
            break
        fi
    done
    [[ -n $SDB_OS_ID ]] && _sdb_evidence "ID=${SDB_OS_ID} ID_LIKE=${SDB_OS_ID_LIKE} VERSION_ID=${SDB_OS_VERSION_ID} CODENAME=${SDB_OS_CODENAME}"

    _sdb_detect_package_tools

    if ((SDB_IS_TERMUX)); then
        sdb_detect_init
        _sdb_finalise_roots
        return 0
    fi

    # 3. Corroborating evidence
    _sdb_corroborate

    # 4. Resolve candidates
    local -a uniq=()
    local c
    for c in "${SDB_DETECT_CANDIDATES[@]:-}"; do
        [[ -n $c ]] || continue
        sdb_in_list "$c" "${uniq[@]:-}" || uniq+=("$c")
    done

    # Legitimate combinations: MX ships MX + Debian evidence by design, and
    # Kali/Parrot are Debian-derived. Precedence resolves those without
    # declaring ambiguity. Two *unrelated* derivatives claiming the same system
    # is genuine ambiguity.
    local -a derivatives=()
    for c in "${uniq[@]:-}"; do
        # An empty element appears when the array is empty under `${a[@]:-}`;
        # counting it would fake a single-candidate result.
        [[ -n $c ]] || continue
        [[ $c == "debian" ]] && continue
        derivatives+=("$c")
    done

    if ((${#derivatives[@]} > 1)); then
        SDB_DETECT_AMBIGUOUS=1
        SDB_PLATFORM="unknown"
        _sdb_evidence "AMBIGUOUS: multiple derivatives claim this system: ${derivatives[*]}"
    elif ((${#derivatives[@]} == 1)); then
        SDB_PLATFORM=${derivatives[0]}
    elif sdb_in_list "debian" "${uniq[@]:-}"; then
        SDB_PLATFORM="debian"
    elif [[ $SDB_OS_ID_LIKE == *debian* ]] || ((SDB_HAS_APT)); then
        # apt existing is NOT sufficient to call something Debian; it is only
        # sufficient to call it a generic Debian-derived system, which is an
        # audit-only classification.
        SDB_PLATFORM="generic-debian"
        _sdb_score 20 "ID_LIKE/apt indicate a Debian-derived system, but ID='${SDB_OS_ID}' is not a supported distribution"
    else
        SDB_PLATFORM="unknown"
    fi

    # Kali Purple is Kali with a variant, never a separate platform.
    if [[ $SDB_PLATFORM == "kali" ]]; then
        if [[ ${SDB_VARIANT,,} == *purple* || ${SDB_OS_PRETTY,,} == *purple* ]] || \
           [[ -d "${root}/usr/share/kali-purple" ]]; then
            SDB_VARIANT="purple"
            _sdb_evidence "Kali variant=purple (treated as Kali, not a separate distribution)"
        fi
    fi

    case $SDB_PLATFORM in
        debian|ubuntu|kali|parrot|mx-linux|generic-debian) SDB_FAMILY="debian" ;;
        *) SDB_FAMILY="unknown" ;;
    esac

    sdb_detect_init
    _sdb_finalise_roots

    # Confidence ceiling, and a floor for the generic classification.
    ((SDB_CONFIDENCE > 100)) && SDB_CONFIDENCE=100
    ((SDB_DETECT_AMBIGUOUS)) && SDB_CONFIDENCE=0
    return 0
}

# _sdb_finalise_roots: set the APT roots and the write allowlist. Everything
# downstream writes only through these.
_sdb_finalise_roots() {
    local root=${SDB_SYS_ROOT%/}
    if ((SDB_IS_TERMUX)); then
        SDB_APT_ETC="${SDB_PREFIX}/etc/apt"
        SDB_WRITE_ROOTS=("${SDB_PREFIX}/etc/apt" "${SDB_PREFIX}/var/lib/secure-debian-bootstrap")
        SDB_KEYRING_DIRS=("${SDB_PREFIX}/etc/apt/trusted.gpg.d" "${SDB_PREFIX}/share/termux-keyring")
    else
        SDB_APT_ETC="${root}/etc/apt"
        SDB_WRITE_ROOTS=("${root}/etc/apt" "${root}/var/lib/secure-debian-bootstrap")
        SDB_KEYRING_DIRS=(
            "${root}/etc/apt/trusted.gpg.d"
            "${root}/etc/apt/keyrings"
            "${root}/usr/share/keyrings"
        )
    fi
    # The state dir is always writable by the run (it is created by us).
    [[ -n ${SDB_STATE_DIR:-} ]] && SDB_WRITE_ROOTS+=("$SDB_STATE_DIR")
    _sdb_evidence "apt_etc=${SDB_APT_ETC}"
    _sdb_evidence "write_roots=${SDB_WRITE_ROOTS[*]}"
}

declare -ga SDB_KEYRING_DIRS=()

# sdb_detection_report: human-readable summary (the Phase 4 required fields).
sdb_detection_report() {
    printf 'Detected platform:     %s\n' "${SDB_PLATFORM:-unknown}"
    printf 'Distribution family:   %s\n' "${SDB_FAMILY:-unknown}"
    printf 'Release name:          %s\n' "${SDB_OS_NAME:-unknown}"
    printf 'Release version:       %s\n' "${SDB_OS_VERSION_ID:-unknown}"
    printf 'Codename:              %s\n' "${SDB_OS_CODENAME:-unknown}"
    printf 'Pretty name:           %s\n' "${SDB_OS_PRETTY:-unknown}"
    printf 'Variant:               %s\n' "${SDB_VARIANT:-none}"
    printf 'Architecture:          %s\n' "${SDB_ARCH:-unknown}"
    printf 'Foreign architectures: %s\n' "${SDB_FOREIGN_ARCHES:-none}"
    printf 'Init system:           %s\n' "${SDB_INIT:-unknown}"
    printf 'Is Termux:             %s\n' "$( ((SDB_IS_TERMUX)) && echo yes || echo no)"
    printf 'Running as root:       %s\n' "$( ((SDB_IS_ROOT)) && echo yes || echo no)"
    printf 'sudo available:        %s\n' "${SDB_SUDO:-no}"
    printf 'Package manager:       %s\n' "${SDB_PKG_MANAGER:-none}"
    printf 'APT config root:       %s\n' "${SDB_APT_ETC:-none}"
    printf 'Keyring directories:   %s\n' "${SDB_KEYRING_DIRS[*]:-none}"
    printf 'Write roots:           %s\n' "${SDB_WRITE_ROOTS[*]:-none}"
    printf 'Confidence:            %s%%\n' "${SDB_CONFIDENCE:-0}"
    printf 'Ambiguous:             %s\n' "$( ((SDB_DETECT_AMBIGUOUS)) && echo yes || echo no)"
    printf 'Evidence:\n'
    local e
    for e in "${SDB_EVIDENCE[@]:-}"; do
        [[ -n $e ]] && printf '  - %s\n' "$e"
    done
    return 0
}

# sdb_detection_json <path>
sdb_detection_json() {
    local out=${1:?} e first=1
    {
        printf '{\n'
        printf '  "platform": "%s",\n' "$(sdb_json_escape "$SDB_PLATFORM")"
        printf '  "family": "%s",\n' "$(sdb_json_escape "$SDB_FAMILY")"
        printf '  "os_id": "%s",\n' "$(sdb_json_escape "$SDB_OS_ID")"
        printf '  "os_id_like": "%s",\n' "$(sdb_json_escape "$SDB_OS_ID_LIKE")"
        printf '  "name": "%s",\n' "$(sdb_json_escape "$SDB_OS_NAME")"
        printf '  "version_id": "%s",\n' "$(sdb_json_escape "$SDB_OS_VERSION_ID")"
        printf '  "codename": "%s",\n' "$(sdb_json_escape "$SDB_OS_CODENAME")"
        printf '  "variant": "%s",\n' "$(sdb_json_escape "$SDB_VARIANT")"
        printf '  "arch": "%s",\n' "$(sdb_json_escape "$SDB_ARCH")"
        printf '  "init": "%s",\n' "$(sdb_json_escape "$SDB_INIT")"
        printf '  "is_termux": %s,\n' "$( ((SDB_IS_TERMUX)) && echo true || echo false)"
        printf '  "is_root": %s,\n' "$( ((SDB_IS_ROOT)) && echo true || echo false)"
        printf '  "apt_etc": "%s",\n' "$(sdb_json_escape "$SDB_APT_ETC")"
        printf '  "confidence": %s,\n' "${SDB_CONFIDENCE:-0}"
        printf '  "ambiguous": %s,\n' "$( ((SDB_DETECT_AMBIGUOUS)) && echo true || echo false)"
        printf '  "evidence": ['
        for e in "${SDB_EVIDENCE[@]:-}"; do
            [[ -n $e ]] || continue
            ((first)) || printf ','
            first=0
            printf '\n    "%s"' "$(sdb_json_escape "$e")"
        done
        printf '\n  ]\n}\n'
    } >"$out"
}

# sdb_require_confident_platform: gate for every modifying stage.
sdb_require_confident_platform() {
    if ((SDB_DETECT_AMBIGUOUS)); then
        sdb_refuse "$SDB_EX_DETECT" \
            "any modification on an ambiguously detected system" \
            "more than one distribution claims this system: ${SDB_DETECT_CANDIDATES[*]:-}" \
            "resolve the conflicting evidence shown above by hand; --yes cannot override this"
    fi
    if [[ $SDB_PLATFORM == "unknown" || -z $SDB_PLATFORM ]]; then
        sdb_refuse "$SDB_EX_DETECT" \
            "any modification on an unidentified system" \
            "platform detection did not identify this system" \
            "run with --audit --verbose and review the evidence list"
    fi
    if ((SDB_CONFIDENCE < SDB_MIN_CONFIDENCE)); then
        sdb_refuse "$SDB_EX_DETECT" \
            "any modification at low detection confidence" \
            "confidence ${SDB_CONFIDENCE}% is below the required ${SDB_MIN_CONFIDENCE}%" \
            "review evidence with --audit --verbose; raise SDB_MIN_CONFIDENCE only if you have verified the platform yourself"
    fi
    return 0
}
