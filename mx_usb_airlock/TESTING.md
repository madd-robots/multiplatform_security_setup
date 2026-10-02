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
$A ingest      # type YES, then REMOVED (the simulator "unplugs" the source)
$A review      # a, APPROVE
$A release     # Enter (the simulator "inserts" the destination), WRITE 0001
$A verify-clean
```

Simulation sessions use a separate state directory (`...-simulation`) and
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
