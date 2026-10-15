#!/usr/bin/env bash
# Backup and rollback: manifest integrity, symlink handling, identity checks,
# path-traversal refusal, and refusal to modify without a verified backup.
# ShellCheck cannot see cross-file use in a sourced library, so variables set
# here and read elsewhere (and vice versa) look unused to it. This is the
# project's one narrowly-justified exception, per docs/operator-guide.md.
# shellcheck disable=SC2034,SC2153
set -uo pipefail
HERE=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P -- "${HERE}/.." && pwd)
# shellcheck source=tests/lib-testing.sh
. "${HERE}/lib-testing.sh"
t_load_libs "$ROOT"
FIX=${SDB_TEST_FIXTURES:-"${HERE}/.fixtures"}
[[ -d $FIX ]] || bash "${HERE}/fixtures/make-fixtures.sh" "$FIX" >/dev/null
sdb_resolve_cmd readlink stat find cp mv install ln rm sha256sum date grep sort >/dev/null 2>&1
SDB_LOG_STARTED=0; SDB_DRY_RUN=0; SDB_IS_ROOT=0; SDB_SUDO=""
printf '== backup and rollback ==\n'

WORK=$(mktemp -d); trap 'rm -rf -- "$WORK"' EXIT

# Work on a writable copy of a fixture so the fixture itself stays pristine.
SYS="${WORK}/sys"
cp -a "${FIX}/debian-stable" "$SYS"

t_reset_detection
SDB_SYS_ROOT=$SYS
sdb_detect_platform >/dev/null 2>&1
SDB_STATE_DIR="${WORK}/state"
SDB_WRITE_ROOTS+=("$SDB_STATE_DIR")
mkdir -p "${SDB_STATE_DIR}/backups"
SDB_RUN_ID="TESTRUN-0001"
SDB_RUN_DIR="${SDB_STATE_DIR}/runs/${SDB_RUN_ID}"
mkdir -p "${SDB_RUN_DIR}/stages"
SDB_TMP_DIR="${SDB_RUN_DIR}/tmp"; mkdir -p "$SDB_TMP_DIR"

# --- no backup yet: modifying stages must refuse ---
SDB_BACKUP_ID=""
out=$( sdb_require_backup 2>&1 ); rc=$?
assert_ne "$rc" "0" "modification is refused before any backup exists"
assert_contains "$out" "without a backup" "refusal names the missing backup"

# --- create the backup ---
sdb_inventory_run >/dev/null 2>&1
sdb_backup_create >/dev/null 2>&1
assert_ne "$SDB_BACKUP_ID" "" "backup id is set"
BDIR="${SDB_STATE_DIR}/backups/${SDB_BACKUP_ID}"
assert_file_exists "${BDIR}/meta.json"        "backup records platform identity"
assert_file_exists "${BDIR}/manifest.tsv"     "backup writes a file manifest"
assert_file_exists "${BDIR}/manifest.sha256"  "backup writes a checksum manifest"
assert_file_exists "${BDIR}/files/etc/apt/sources.list.d/debian.sources" "the APT config is archived"

# --- manifest verifies ---
assert_true "sdb_backup_verify '$SDB_BACKUP_ID'" "a fresh backup verifies"
assert_true "sdb_require_backup" "modification is permitted once a verified backup exists"

# --- tampering is detected ---
echo "tampered" >>"${BDIR}/files/etc/apt/sources.list.d/debian.sources"
assert_false "sdb_backup_verify '$SDB_BACKUP_ID'" "tampering with the archive fails verification"
out=$( sdb_require_backup 2>&1 ); rc=$?
assert_ne "$rc" "0" "modification is refused when the backup fails verification"
# restore the archive so later tests work from a good backup
sed -i '$ d' "${BDIR}/files/etc/apt/sources.list.d/debian.sources"
assert_true "sdb_backup_verify '$SDB_BACKUP_ID'" "backup verifies again after the tamper is reverted"

# --- backup preserves symlinks as symlinks ---
SYS2="${WORK}/sys2"; cp -a "${FIX}/hostile" "$SYS2"
t_reset_detection; SDB_SYS_ROOT=$SYS2
sdb_detect_platform >/dev/null 2>&1
SDB_WRITE_ROOTS+=("$SDB_STATE_DIR")
SDB_RUN_ID="TESTRUN-0002"; SDB_RUN_DIR="${SDB_STATE_DIR}/runs/${SDB_RUN_ID}"
mkdir -p "${SDB_RUN_DIR}/stages"; SDB_TMP_DIR="${SDB_RUN_DIR}/tmp"; mkdir -p "$SDB_TMP_DIR"
sdb_inventory_run >/dev/null 2>&1
sdb_backup_create >/dev/null 2>&1
HB="${SDB_STATE_DIR}/backups/${SDB_BACKUP_ID}"
assert_true "[[ -L '${HB}/files/etc/apt/trusted.gpg.d/escape.gpg' ]]" \
    "a symlink is archived as a symlink, not followed"
assert_file_absent "${HB}/files/secret/data" "the symlink target outside APT config is NOT copied"
manifest=$(cat "${HB}/manifest.tsv")
assert_contains "$manifest" "symlink" "the manifest records the symlink type"

# --- rollback refuses a foreign backup ---
SDB_PLATFORM="ubuntu"   # pretend we are now a different system
out=$( sdb_rollback_check_identity "$HB" 2>&1 ); rc=$?
assert_ne "$rc" "0" "rollback refuses a backup taken on a different platform"
assert_contains "$out" "different platform" "refusal explains the platform mismatch"
SDB_PLATFORM="debian"

# --- rollback refuses traversal in a manifest ---
EVIL="${SDB_STATE_DIR}/backups/EVIL"
mkdir -p "${EVIL}/files"
cp "${HB}/meta.json" "${EVIL}/meta.json"
printf '#relpath\ttype\tmode\towner\tgroup\tmtime\tlink_target\n' >"${EVIL}/manifest.tsv"
printf '../../../../etc/shadow\tfile\t0644\troot\troot\t0\t-\n' >>"${EVIL}/manifest.tsv"
: >"${EVIL}/manifest.sha256"
SDB_DRY_RUN=1
out=$( sdb_rollback_apply "EVIL" 2>&1 ); rc=$?
assert_not_contains "$out" "restore /etc/shadow" "traversal entry is never restored"
assert_contains "$out" "unsafe manifest path" "traversal entry is reported as unsafe"
SDB_DRY_RUN=0

# --- rollback actually restores ---
t_reset_detection; SDB_SYS_ROOT=$SYS
sdb_detect_platform >/dev/null 2>&1
SDB_WRITE_ROOTS+=("$SDB_STATE_DIR")
SDB_RUN_ID="TESTRUN-0003"; SDB_RUN_DIR="${SDB_STATE_DIR}/runs/${SDB_RUN_ID}"
mkdir -p "${SDB_RUN_DIR}/stages"; SDB_TMP_DIR="${SDB_RUN_DIR}/tmp"; mkdir -p "$SDB_TMP_DIR"
sdb_inventory_run >/dev/null 2>&1
sdb_backup_create >/dev/null 2>&1
GOOD=$SDB_BACKUP_ID
target="${SYS}/etc/apt/sources.list.d/debian.sources"
original=$(cat "$target")
printf 'deb http://evil.example.net/debian trixie main\n' >"$target"
assert_ne "$(cat "$target")" "$original" "the file was modified before rollback"
sdb_rollback_apply "$GOOD" >/dev/null 2>&1
assert_eq "$(cat "$target")" "$original" "rollback restores the original content"

# --- backups are never deleted by a rollback ---
assert_file_exists "${SDB_STATE_DIR}/backups/${GOOD}/meta.json" "the backup survives being used"

t_summary
