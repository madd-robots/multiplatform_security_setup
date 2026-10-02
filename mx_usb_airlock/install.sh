#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Installer for the MX USB Transfer Airlock.
#
#   sudo ./install.sh                 system install: /opt/mx_usb_airlock + /usr/local/bin/mx-usb-airlock
#   ./install.sh                      user install:   ~/.local/share/mx_usb_airlock + ~/.local/bin/mx-usb-airlock
#   ./install.sh --check-only         verify the bundle and prerequisites, change nothing
#   sudo ./install.sh --uninstall     remove an installation made by this script
#
# This script never downloads anything, never installs packages, and never
# creates services, timers, udev rules, desktop autostart entries or shell
# profile changes.  It only copies the verified bundle files and writes one
# small launcher.

set -euf
umask 022
ORIG_PATH=${PATH:-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

APP=mx_usb_airlock
VERSION=1.1.0
LAUNCHER_NAME=mx-usb-airlock
MARKER="# mx_usb_airlock launcher - managed by install.sh"
INSTALL_MARKER=.installed-by-mx_usb_airlock
PAYLOAD="airlock.py config.example.json README.md SECURITY_MODEL.md RECOVERY.md TESTING.md LICENSE install.sh tests/test_airlock.py tests/test_install.py tests/test_integration_destructive.py tests/test_v11.py termux/usb_airlock_prepare.py"

info() { printf '[INFO] %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARNING] %s\n' "$*" >&2; }
die() { printf '[BLOCKING] %s\n' "$*" >&2; exit 1; }
cancel() { printf '[WARNING] Cancelled: %s\n' "$*" >&2; exit 2; }

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --prefix DIR          installation directory (its last component must contain "mx_usb_airlock")
  --bin-dir DIR         directory for the mx-usb-airlock launcher
  --expect-digest HEX   required bundle digest (SHA-256 of SHA256SUMS); install stops on mismatch
  --skip-tests          do not run the bundled test suite before installing
  --check-only          verify bundle and prerequisites only; change nothing
  --uninstall           remove an installation previously made by this script
  -y, --yes             do not ask for confirmation
  -h, --help            show this help

Defaults: as root /opt/mx_usb_airlock and /usr/local/bin;
otherwise ~/.local/share/mx_usb_airlock and ~/.local/bin.
EOF
}

MODE=install
ASSUME_YES=0
RUN_TESTS=1
PREFIX=""
BIN_DIR=""
EXPECT_DIGEST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
        --bin-dir) [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR=$2; shift 2 ;;
        --expect-digest) [ $# -ge 2 ] || die "--expect-digest needs a value"; EXPECT_DIGEST=$2; shift 2 ;;
        --skip-tests) RUN_TESTS=0; shift ;;
        --check-only) MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option (see --help)" ;;
    esac
done

case "$0" in
    */*) SELF_DIR=${0%/*} ;;
    *) SELF_DIR=. ;;
esac
SRC_DIR=$(cd -- "$SELF_DIR" && pwd -P)

EUID_NUM=$(id -u)
if [ "$EUID_NUM" -eq 0 ]; then
    [ -n "$PREFIX" ] || PREFIX=/opt/$APP
    [ -n "$BIN_DIR" ] || BIN_DIR=/usr/local/bin
else
    [ -n "${HOME:-}" ] || die "HOME is not set; use --prefix and --bin-dir"
    [ -n "$PREFIX" ] || PREFIX=$HOME/.local/share/$APP
    [ -n "$BIN_DIR" ] || BIN_DIR=$HOME/.local/bin
fi

# Paths are restricted to a plain character set so they can be embedded in
# the launcher and passed to rm/mv without any quoting surprises.
check_path() {
    case "$2" in
        /*) ;;
        *) die "$1 must be an absolute path" ;;
    esac
    case "$2" in
        *[!A-Za-z0-9._/-]*) die "$1 may only contain A-Z a-z 0-9 . _ - / (got an unsupported character)" ;;
    esac
    case "$2" in
        */../*|*/..|*/./*|*/.|*//*|*/) die "$1 must be a normalised path without . or .. components or a trailing /" ;;
    esac
    [ "$2" != "/" ] || die "$1 must not be /"
}
check_path --prefix "$PREFIX"
check_path --bin-dir "$BIN_DIR"
case "${PREFIX##*/}" in
    *"$APP"*) ;;
    *) die "--prefix must end in a directory whose name contains $APP (protects against removing unrelated directories)" ;;
esac
LAUNCHER=$BIN_DIR/$LAUNCHER_NAME

have_tool() {
    for d in /usr/sbin /usr/bin /sbin /bin; do
        if [ -x "$d/$1" ]; then
            return 0
        fi
    done
    return 1
}

confirm() {
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    [ -t 0 ] || cancel "no terminal for confirmation; re-run with --yes to proceed"
    printf '%s [y/N] ' "$1"
    ans=""
    read -r ans || ans=""
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *) cancel "operator declined" ;;
    esac
}

launcher_is_managed() {
    [ -f "$LAUNCHER" ] && [ ! -L "$LAUNCHER" ] && grep -qxF "$MARKER" "$LAUNCHER"
}

# ---------------------------------------------------------------- uninstall
if [ "$MODE" = uninstall ]; then
    if [ -L "$PREFIX" ] || [ ! -f "$PREFIX/$INSTALL_MARKER" ]; then
        die "no installation made by this script was found at $PREFIX"
    fi
    info "Will remove: $PREFIX"
    if launcher_is_managed; then
        info "Will remove: $LAUNCHER"
    elif [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
        warn "$LAUNCHER is not managed by this installer and will be left alone"
    fi
    confirm "Remove the MX USB Transfer Airlock installation?"
    rm -rf -- "$PREFIX"
    if launcher_is_managed; then
        rm -f -- "$LAUNCHER"
    fi
    pass "Uninstalled."
    info "Session state and quarantine (tmpfs under XDG_RUNTIME_DIR or /dev/shm) are not touched; they vanish at reboot."
    exit 0
fi

# ---------------------------------------------------------- bundle integrity
info "MX USB Transfer Airlock $VERSION installer"
info "Bundle directory: $SRC_DIR"
have_tool sha256sum || die "sha256sum is required (coreutils)"
cd -- "$SRC_DIR"
for f in SHA256SUMS $PAYLOAD; do
    if [ -L "$f" ] || [ ! -f "$f" ]; then
        die "bundle file missing or not a regular file: $f"
    fi
done
if grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._/-]+$' SHA256SUMS; then
    die "SHA256SUMS contains malformed lines"
fi
LISTED=$(sed -e 's/^[0-9a-f]\{64\}  //' SHA256SUMS | sort)
EXPECTED=$(printf '%s\n' $PAYLOAD | sort)
[ "$LISTED" = "$EXPECTED" ] || die "SHA256SUMS does not list exactly the expected bundle files"
sha256sum --check --strict --quiet SHA256SUMS || die "bundle integrity check FAILED: a file does not match SHA256SUMS"
pass "All $(printf '%s\n' $PAYLOAD | wc -l | tr -d ' ') bundle files match SHA256SUMS."
DIGEST=$(sha256sum SHA256SUMS | cut -d' ' -f1)
info "Bundle digest (SHA-256 of SHA256SUMS): $DIGEST"
if [ -n "$EXPECT_DIGEST" ]; then
    EXPECT_LC=$(printf '%s' "$EXPECT_DIGEST" | tr 'A-F' 'a-f')
    [ "$EXPECT_LC" = "$DIGEST" ] || die "bundle digest does NOT match --expect-digest; do not install this bundle. Note: --expect-digest takes the BUNDLE DIGEST (SHA-256 of SHA256SUMS, published as mx_usb_airlock-$VERSION.SHA256SUMS.sha256), not the archive SHA-256."
    pass "BUNDLE DIGEST MATCHES THE EXPECTED VALUE"
else
    warn "SHA256SUMS only detects corruption. To detect tampering, compare the digest above (or the .tar.gz SHA-256) with a value obtained independently, or pass --expect-digest."
fi
BUNDLE_VERSION=$(sed -n 's/^APP_VERSION = "\([0-9A-Za-z.+-]*\)"$/\1/p' airlock.py)
[ "$BUNDLE_VERSION" = "$VERSION" ] || die "installer version $VERSION does not match airlock.py version $BUNDLE_VERSION"

# ------------------------------------------------------------ prerequisites
PY=""
for candidate in /usr/bin/python3 /bin/python3; do
    if [ -x "$candidate" ]; then
        PY=$candidate
        break
    fi
done
[ -n "$PY" ] || die "python3 not found in /usr/bin (on MX/Debian: sudo apt install python3)"
[ "$(stat -L -c %u -- "$PY")" = 0 ] || die "$PY is not owned by root; refusing to use it"
"$PY" -I -B -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required"
pass "Python: $("$PY" -I -B -c 'import sys; print(sys.version.split()[0])') at $PY"

MISSING=""
for t in lsblk mount umount blockdev; do
    have_tool "$t" || MISSING="$MISSING $t"
done
if [ "$EUID_NUM" -ne 0 ]; then
    have_tool sudo || MISSING="$MISSING sudo"
fi
if [ -n "$MISSING" ]; then
    die "required tools missing:$MISSING (on MX/Debian they come from util-linux, mount and sudo; nothing was installed)"
fi
pass "Required tools present: lsblk mount umount blockdev"
AUTH_MISSING=""
for t in minisign age age-keygen; do
    have_tool "$t" || AUTH_MISSING="$AUTH_MISSING $t"
done
if [ -n "$AUTH_MISSING" ]; then
    warn "Authenticated V1.1 transfers (the default) need:$AUTH_MISSING. On MX/Debian: sudo apt install minisign age (no upgrade; nothing was installed by this script). Only 'ingest --legacy' works without them."
else
    pass "Authenticated-transfer tools present: minisign age age-keygen"
fi
OPTIONAL_MISSING=""
for t in udevadm ip rfkill nft clamscan wipefs sfdisk mkfs.vfat; do
    have_tool "$t" || OPTIONAL_MISSING="$OPTIONAL_MISSING $t"
done
if [ -n "$OPTIONAL_MISSING" ]; then
    info "Optional tools not found (features degrade gracefully):$OPTIONAL_MISSING"
fi

# ----------------------------------------------------------------- tests
if [ "$RUN_TESTS" -eq 1 ]; then
    info "Running the bundled test suite (simulation only; no real device is touched)..."
    TEST_LOG=$(mktemp)
    if (cd -- "$SRC_DIR" && "$PY" -I -B -m unittest discover -s tests) >"$TEST_LOG" 2>&1; then
        pass "Test suite: $(grep -E '^Ran [0-9]+ tests' "$TEST_LOG" || printf 'completed')"
        rm -f -- "$TEST_LOG"
    else
        tail -n 30 -- "$TEST_LOG" >&2
        rm -f -- "$TEST_LOG"
        die "the bundled test suite FAILED; nothing was installed"
    fi
fi

if [ "$MODE" = check ]; then
    pass "Check complete. Nothing was changed."
    exit 0
fi

# --------------------------------------------------------------- install
if [ -L "$PREFIX" ]; then
    die "$PREFIX is a symlink; refusing"
fi
if [ -e "$PREFIX" ] && [ ! -f "$PREFIX/$INSTALL_MARKER" ]; then
    die "$PREFIX exists but was not installed by this script; refusing to overwrite it"
fi
if { [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; } && ! launcher_is_managed; then
    die "$LAUNCHER exists and is not managed by this installer; refusing to overwrite it"
fi

if [ "$EUID_NUM" -ne 0 ]; then
    warn "User install: files are writable by your account, so anything running as you could modify them. A system install (sudo ./install.sh) is recommended."
fi
info "Install directory: $PREFIX"
info "Launcher:          $LAUNCHER"
confirm "Install MX USB Transfer Airlock $VERSION?"

PARENT=${PREFIX%/*}
[ -n "$PARENT" ] || PARENT=/
mkdir -p -- "$PARENT" "$BIN_DIR"
STAGE=$(mktemp -d "$PARENT/.$APP.stage.XXXXXX")
cleanup() {
    if [ -n "${STAGE:-}" ] && [ -d "$STAGE" ]; then
        rm -rf -- "$STAGE"
    fi
    if [ -n "${LAUNCHER_TMP:-}" ] && [ -f "$LAUNCHER_TMP" ]; then
        rm -f -- "$LAUNCHER_TMP"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir -m 0755 -- "$STAGE/tests" "$STAGE/termux"
for f in $PAYLOAD SHA256SUMS; do
    install -m 0644 -- "$SRC_DIR/$f" "$STAGE/$f"
done
chmod 0755 -- "$STAGE" "$STAGE/install.sh"
(cd -- "$STAGE" && sha256sum --check --strict --quiet SHA256SUMS) || die "installed copy failed verification"
{
    printf 'app=%s\n' "$APP"
    printf 'version=%s\n' "$VERSION"
    printf 'bundle_digest=%s\n' "$DIGEST"
    printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'launcher=%s\n' "$LAUNCHER"
} > "$STAGE/$INSTALL_MARKER"
chmod 0644 -- "$STAGE/$INSTALL_MARKER"

OLD=""
if [ -e "$PREFIX" ]; then
    OLD=$PREFIX.old.$$
    mv -- "$PREFIX" "$OLD"
fi
mv -- "$STAGE" "$PREFIX"
STAGE=""
if [ -n "$OLD" ]; then
    rm -rf -- "$OLD"
fi
pass "Files installed in $PREFIX"

LAUNCHER_TMP=$(mktemp "$BIN_DIR/.$LAUNCHER_NAME.XXXXXX")
printf '#!/bin/sh\n%s\n# Runs the airlock in Python isolated mode. Documentation: %s/README.md\nexec %s -I -B %s/airlock.py "$@"\n' \
    "$MARKER" "$PREFIX" "$PY" "$PREFIX" > "$LAUNCHER_TMP"
chmod 0755 -- "$LAUNCHER_TMP"
mv -f -- "$LAUNCHER_TMP" "$LAUNCHER"
LAUNCHER_TMP=""

INSTALLED_VERSION=$("$LAUNCHER" --version 2>&1) || die "the installed launcher did not run"
pass "Launcher works: $INSTALLED_VERSION"
case ":$ORIG_PATH:" in
    *":$BIN_DIR:"*) ;;
    *) info "$BIN_DIR is not on your PATH; run the launcher as $LAUNCHER (no shell profile was changed)." ;;
esac
info "Next: read $PREFIX/README.md and $PREFIX/SECURITY_MODEL.md, then run: $LAUNCHER_NAME status"
exit 0
