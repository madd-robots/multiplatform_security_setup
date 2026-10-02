# Testing

## Automated tests (no real devices)

```
cd mx_usb_airlock
python3 -I -B -m unittest discover -s tests -v
```

The suite uses `SimulatedBackend`: simulated block devices whose
"filesystems" are temporary directories. No block device is mounted, changed
or written. Fault injection (identity changes, unmounts, I/O errors,
corruption) uses the simulator's event hooks. A small read-only smoke test
also enumerates the host's real devices (`lsblk`, mountinfo, sysfs) without
mounting or changing anything. It is skipped where `lsblk` is missing.

### Required scenarios and their tests (`tests/test_airlock.py`)

| Scenario | Test(s) |
|---|---|
| Normal approved .ps1 transfer | `test_normal_ps1_transfer` |
| Hash-match success | `test_trusted_hash_match` |
| Hash mismatch | `test_trusted_hash_mismatch_blocks_release`, `test_operator_entered_hash_mismatch_is_sticky` |
| Malicious filename | `test_malicious_names_rejected`, `test_malicious_and_unicode_filenames_left_behind` |
| ../ traversal | `test_relative_path_traversal_and_absolute`, `test_destination_writer_path_safety`, `test_unsafe_or_conflicting_entries_rejected` |
| Absolute paths | `test_relative_path_traversal_and_absolute`, `test_destination_writer_path_safety` |
| Symlink source | `test_symlink_source_not_followed` |
| Symlink destination | `test_symlink_destination_not_followed`, `test_destination_writer_path_safety`, `test_quarantine_symlink_swap_detected` |
| Fake .txt containing PE | `test_fake_txt_containing_pe_rejected`, `test_fake_txt_and_nul_ps1_rejected` |
| NUL-heavy fake PowerShell | `test_nul_heavy_powershell_rejected`, `test_fake_txt_and_nul_ps1_rejected` |
| Both source and destination present | `test_both_devices_present_at_ingest`, `test_both_devices_present_at_release`, `test_release_refuses_preinserted_devices`, `test_status_reports_coexistence` |
| Device identity changing mid-run | `test_source_identity_change_mid_run`, `test_destination_identity_change_mid_run`, `test_protected_device_during_revalidation_blocks` |
| Destination hash mismatch | `test_destination_hash_mismatch`, `test_destination_unexpected_extra_file_detected` |
| Unexpected unmount | `test_unexpected_unmount_during_scan`, `test_device_removed_during_scan` |
| Source mounted RW | `test_source_automounted_read_write`, `test_source_automounted_read_write_operator_stops`, `test_concurrent_remount_before_mount_blocks` |
| Missing ClamAV | `test_missing_clamav_is_not_fatal` (plus `test_clamav_detection_blocks_file`) |
| Malicious Unicode filename | `test_malicious_unicode_names_rejected`, `test_malicious_and_unicode_filenames_left_behind` |
| Duplicate filename collision | `test_duplicate_filename_collision` |
| Zero-byte file | `test_zero_byte`, `test_zero_byte_file_quarantined_with_flag` |
| Large unexpected file | `test_large_unexpected_file_rejected` |
| Unsupported file type | `test_extension_policy`, `test_unsupported_types_and_metadata_left_behind`, `test_denied_extension_cannot_be_allowlisted` |
| Attempt to select system disk | `test_system_disk_cannot_be_selected` |
| Attempt to select live boot disk | `test_live_boot_disk_cannot_be_selected_and_does_not_count`, `test_undetected_live_media_in_use_is_never_offered` |
| Operator cancellation | `test_operator_cancellation_at_identity`, `test_operator_cancellation_eof`, `test_wrong_write_phrase_writes_nothing`, `test_noninteractive_fails_closed` |

Further tests cover the source-still-present gate, quarantine tampering,
block-layer read-only failure, special files, trusted hash files on the dirty
drive or inside the quarantine, untrusted source-supplied hash lists,
destination policy (read-only, no serial, unsupported filesystem),
`prepare-clean-usb`, network lockdown and restore, the installed-OS warning,
state-directory permissions, I/O errors during release, parsers, the
PowerShell review patterns, and source hygiene. The hygiene test checks that
there are no backticks, no `shell=True`, and no eval, exec, pickle,
`os.system` or `bash -c`. It also checks that no shell interpretation happens
(shell metacharacters are passed literally to a real `echo`).

### V1.1 (`tests/test_v11.py`)

Uses the real `minisign` and `age` binaries with throw-away keys in temporary
directories. No production key exists in the tests. The classes are skipped
when those tools are missing.

| Area | Tests (class) |
|---|---|
| Termux: valid package, SHA-256 values, signature, no secret key or plaintext in the package, deterministic manifest/container, duplicate/absolute/`..` paths, symlink, FIFO, socket, device node (where permitted), hard link, malformed/Unicode names, zero-byte and large files, spaces/leading dash/shell metacharacters (round-tripped without interpretation), key overwrite and overlap protection | `TermuxPreparationTests` |
| Pinning by fingerprint (a forged key with a copied key ID is refused), explicit replacement, private non-overwritten transport identity, keys required before any device access, keys on the transport USB refused | `KeyPinningTests` |
| Valid end-to-end transfer; modified manifest/signature, malformed signature, wrong key, modified/swapped payload, re-signed payload hash, comment binding, transfer ID mismatch, duplicate entries and JSON keys, malformed/oversized manifest, unknown version, traversal/absolute paths, files differing from the signed manifest, content-policy violation, package structure, symlinked member, missing package, no silent downgrade, incomplete set, staging tampered before export, key changed before export | `AuthenticatedTransferTests` |
| Wrong identity, truncated/modified/empty ciphertext, partial decrypt failure after the first chunk, unexpected plaintext (non-tar, extra/symlink/hardlink/dir/FIFO/device/absolute/traversal/missing members), no plaintext left behind on failure | `EncryptionTests` |
| Pre-existing root file, `autorun.inf`, executable, hidden file, directory, `System Volume Information`; contamination during export (outside or inside the transfer directory, hidden, `.lnk`, `autorun.inf`, executable); modified or removed file; file added after release; forwarded signed manifest altered; allowlist mechanism exact and empty | `WholeDestinationTests` |
| Block read-only set, verification failure, mount not read-only, missing `noexec`/`nodev`/`nosuid`, device becomes writable, device disappears, identity change, kernel superblock `ro` required | `ReadOnlyTests` |
| Gates cannot be skipped, reordered or repeated; release needs the removal gate; V1.0 session migration; V1.0 config still loads; no bypass options | `GateStateMachineTests`, `V11SourceHygieneTests` |

Intentional updates to V1.0 tests:
- `tests/test_airlock.py` now calls `ingest --legacy`, because the default
  ingest is authenticated.
- `test_block_readonly_failure_is_a_hard_stop` replaces the PROCEED-override
  test.
- The quarantine permission test expects sealed 0500/0400 permissions.
- The planted-symlink destination test now expects `DESTINATION_NOT_CLEAN`.
- Findings are reported as whole-filesystem paths.

Each of these changes is commented in the test.

### PR #3 review findings

`PullRequestReviewRegressionTests` in `tests/test_airlock.py` has a test named
`test_f<N>_...` for each of review findings 1 to 10.
`test_f11_archive_hash_and_bundle_digest_are_distinct_and_documented` in
`tests/test_install.py` covers finding 11. Each of these tests was confirmed
to fail on the code before the fixes.

### Bundle and installer (`tests/test_install.py`)

These tests build the release tarball into a temporary directory, extract it,
and run `install.sh` against temporary prefixes. They check:

- the build is reproducible, and the archive holds only root-owned regular
  files and directories with relative paths
- install, upgrade and uninstall work, and the launcher runs `-I -B`
- tampered files, missing files and a wrong `--expect-digest` are refused
- an unmanaged prefix or launcher is never overwritten
- unsafe paths are rejected
- `--check-only` changes nothing
- a non-interactive run without `--yes` is cancelled

They are skipped inside an installed bundle, because `tools/` is not shipped.

## Practice run with the simulator (CLI)

```
mkdir -p /tmp/airsim/src /tmp/airsim/dst /tmp/airsim/live
printf 'Write-Host hello\r\n' > /tmp/airsim/src/test.ps1
cat > /tmp/airsim/scenario.json <<'EOF'
{"devices": [
  {"role": "live",        "kname": "sda", "serial": "LIVE0001",  "root": "live"},
  {"role": "source",      "kname": "sdb", "serial": "DIRTY0001", "model": "Dirty", "root": "src"},
  {"role": "destination", "kname": "sdc", "serial": "CLEAN0001", "model": "Clean", "root": "dst"}
]}
EOF
A="python3 -I -B airlock.py --simulate /tmp/airsim/scenario.json"
$A ingest --legacy   # type YES, then REMOVED (the simulator "unplugs" the source)
$A review      # a, APPROVE
$A release     # Enter (the simulator "inserts" the destination), WRITE 0001
$A verify-clean
```

The CLI simulator demonstrates the V1.0 flow with `ingest --legacy` (authenticated
packages need the MX keys; see README). Simulation sessions use a separate state directory (`...-simulation`) and
cannot be mixed with real-device sessions. Optional device keys: `model`,
`vendor`, `size`, `fstype`, `tran`, and `automount` (`"rw"` or `"ro"`, source
only). Prompts need an interactive terminal: piped input is refused by design.

## Destructive integration test (real device, opt-in only)

`tests/test_integration_destructive.py` **erases** one dedicated USB test
drive. It runs only when all of these hold:

- `AIRLOCK_TEST_DEVICE=/dev/disk/by-id/usb-...` names the drive,
- `AIRLOCK_TEST_DESTRUCTIVE=ERASE-THIS-TEST-DEVICE` is set,
- it runs as root on Linux, and
- that drive is the only removable storage attached, is USB, and is not
  protected (system or live).

```
sudo AIRLOCK_TEST_DEVICE=/dev/disk/by-id/usb-XYZ-0:0 \
     AIRLOCK_TEST_DESTRUCTIVE=ERASE-THIS-TEST-DEVICE \
     python3 -I -B -m unittest tests.test_integration_destructive -v
```

It formats FAT32, writes through `DestinationWriter`, verifies through a
read-only remount, sets the block device read-only, ingests it, and confirms
that a read-write mount then fails. Unplug and replug the drive afterwards.
This test has not been run in the development container, which has no USB
hardware.
