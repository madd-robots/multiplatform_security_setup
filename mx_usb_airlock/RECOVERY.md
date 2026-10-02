# Recovery and troubleshooting

The airlock stops (fails closed) whenever something is not as expected. This
page lists what to do in each case. Run `python3 -I -B airlock.py status`
first: it shows the session phase and the next step.

## Disabling desktop automount (recommended, manual)

The airlock never changes desktop settings. To turn automount off yourself:

- **MX Linux Xfce:** Settings Manager -> *Removable Drives and Media* ->
  untick *Mount removable drives when hot-plugged* and *Mount removable media
  when inserted*.
- **MX Linux KDE:** System Settings -> *Disks & Cameras / Device Actions /
  Removable Storage* -> turn off automatic mounting.
- **Fluxbox / other:** stop any auto-mounter (for example `udiskie`) for this
  session.

On a live session these changes are lost at reboot.

## Common blocking messages

| Message | Meaning and action |
|---|---|
| `MULTIPLE_REMOVABLE_DEVICES` | More than one removable drive is attached. Remove everything except the one the step asks for. If one of them is your live boot stick and it was not detected, add `--live-device /dev/disk/by-id/<its link>`. |
| `IN USE (mounted at ...)` in `status` | That disk is mounted somewhere other than a desktop location, so it is treated as part of the system. If it is your dirty USB that you mounted by hand, unmount it (`sudo umount <path>`) and retry. |
| `SESSION_ACTIVE` | An unfinished session exists. Finish it, or start over with `ingest --new-session` (its quarantine is deleted). |
| `SOURCE_STILL_PRESENT`, `DIRTY USB STILL DETECTED` | The dirty drive is still attached. Unplug it physically, then confirm again. |
| `REMOVABLE_DEVICE_ALREADY_PRESENT` | `release` found a drive before asking for one. Remove all USB storage, run `release` again, and insert the clean USB only when prompted. |
| `DESTINATION_IS_SOURCE` | The inserted drive matches the dirty drive (serial, by-id, filesystem UUID, or model+vendor+size without serials). Use a different, clearly labelled drive. |
| `IDENTITY_UNCERTAIN` | The destination reports no usable serial number. Use a drive that does. |
| `DESTINATION_READ_ONLY` | The drive is read-only at the block layer. It may be the dirty drive, which ingest set read-only. Unplug and check which drive it is. |
| `UNSUPPORTED_FILESYSTEM` | Destination is not FAT32 or exFAT. Run `prepare-clean-usb` (this erases the drive) or format it on trusted equipment. |
| `UNEXPECTED_REMOVABLE_DEVICE` | Another removable drive appeared while a device was being processed. This includes a drive that is mounted somewhere such as `/mnt`. The step stopped before going further. Remove the extra drive and repeat the step. If this happened during `release`, treat the clean USB's transfer directory as unverified. |
| `OFFLINE_LOCKDOWN_INCOMPLETE` | The requested offline lockdown could not be confirmed: the network state is unknown, an interface could not be brought down, or interfaces or a default route are still active. Changes made so far are saved, so run `network-restore`, take the network down manually (unplug cables, switch radios off), and try again. |
| `BUFFER_FLUSH_FAILED` | `blockdev --flushbufs` failed or is missing, so the read-back could not be trusted and no verification was claimed. Treat the clean USB as unverified and retry `release`. |
| `STATE_TOO_LARGE` | The session state would exceed its size limit. Lower `max_scan_entries` or `max_files`, or remove clutter from the source, then start a new session. |
| `NO_AUTHENTICATED_PACKAGE` | The USB has no `AIRLOCK_TRANSFER/` package. Prepare one on Termux. For a deliberate V1.0-style unauthenticated transfer, use `ingest --legacy`. |
| `AUTHENTICATED_PACKAGE_IN_LEGACY_MODE` | You ran `--legacy` on a USB that carries a signed package. Run the default (authenticated) `ingest`. |
| `NO_TRUSTED_SIGNING_KEY`, `NO_TRANSPORT_IDENTITY` | MX keys are not set up. Run `init-transport-key` and `trust-signing-key` (see README). |
| `WRONG_SIGNING_KEY`, `SIGNATURE_INVALID`, `SIGNATURE_MALFORMED`, `SIGNATURE_BINDING_MISMATCH` | The package was not signed by the pinned Termux key, or was modified after signing. Treat it as hostile. Re-create it on Termux. If the signing key really changed, pin the new one deliberately with `trust-signing-key --replace`. |
| `MANIFEST_MALFORMED`, `MANIFEST_UNSUPPORTED_VERSION`, `MANIFEST_DUPLICATE_PATH`, `TRANSFER_ID_MISMATCH`, `PACKAGE_STRUCTURE_INVALID` | The package is malformed, or comes from an incompatible version. Re-create it with the matching `usb_airlock_prepare`. |
| `ENCRYPTED_PAYLOAD_MISMATCH` | `payload.age` is not the payload that was signed (modified, truncated or swapped). Re-copy the package from Termux. |
| `DECRYPTION_FAILED` | The package was encrypted for a different MX recipient, or the ciphertext is damaged. Check `show-keys` on both sides. |
| `DECRYPTED_FILE_MISMATCH`, `PAYLOAD_UNSAFE_MEMBER`, `PAYLOAD_UNEXPECTED_MEMBER`, `PAYLOAD_CONTAINER_INVALID` | The decrypted contents differ from the signed manifest. Nothing was staged. Re-create the package. |
| `SIGNED_FILE_POLICY_VIOLATION` | A signed file breaks the content policy (for example a binary signature). The set moves as a whole, so nothing was staged. Fix the file set on Termux. |
| `BLOCK_READONLY_FAILED`, `BLOCK_READONLY_LOST`, `MOUNT_OPTIONS_NOT_ENFORCED` | The required read-only protection could not be established or was lost. There is no override. Try another USB port or reader. Do not use a device that refuses read-only mode. |
| `DESTINATION_NOT_CLEAN` | The clean USB is not empty. Nothing was written or deleted. Erase it deliberately with `prepare-clean-usb`, or use another drive. |
| `DESTINATION_CONTAMINATION` | Unauthorized content appeared on the clean USB during export. Do not use it. Erase it with `prepare-clean-usb` and release again. Suspect the MX host. |
| `SIGNING_KEY_CHANGED`, `SIGNED_SET_INCOMPLETE`, `ILLEGAL_TRANSITION` | The release preconditions changed or were skipped. Start a new session. |
| `SESSION_FROM_V1_0` | A session created by V1.0.0 is still open. Run `ingest --new-session` or `discard-session`; its logs and reports are kept. |
| `CONCURRENT_MOUNT` | Something (usually automount) mounted the drive again during the process. Disable automount and start the step again. |
| `TRUSTED_HASH_MISMATCH` | A file does not match the hash you supplied. Treat it as tampered. Release stays blocked for this session. Get a known-good copy and start a new session. |
| `TRUSTED_HASH_ON_REMOVABLE`, `TRUSTED_HASH_FROM_DIRTY_MEDIA` | The trusted hash file must be created or typed on the live system, not taken from the dirty USB or the quarantine. |
| `QUARANTINE_TAMPERED` | Quarantined content changed after ingest. The session is blocked. Assume the running system is not trustworthy. Reboot into fresh live media and start again. |
| `DESTINATION_VERIFICATION_MISMATCH` | What was read back differs from what was written. The clean USB holds an unverified directory: do not use it. Erase the drive (`prepare-clean-usb`) or use another one, then run `release` again (the session allows a retry). |
| `MOUNT_FAILED`, `UNMOUNT_FAILED` | See the `stderr` text shown. A corrupt or hostile filesystem may refuse to mount. Do not force it. |
| `STATE_DIR_INVALID` | The state directory is not a private 0700 directory owned by you. Choose another with `--state-dir`. |
| `PRIVILEGE_UNAVAILABLE` | `sudo` is missing or authentication failed. Use a root shell on the live system. |

## Leftover mounts after a crash

The airlock's mount points live under the state directory (shown by `status`),
for example `/run/user/1000/mx_usb_airlock/mnt/source` and `.../mnt/dest`.
Check with `findmnt | grep mx_usb_airlock` and unmount with
`sudo umount <that path>`.

## The dirty drive stays read-only

`blockdev --setro` lasts until the drive is unplugged. Unplugging it, which
the workflow requires anyway, clears the flag.

## Network

If you used `--offline-lockdown` or `network-lockdown`, run
`python3 -I -B airlock.py network-restore`. The prior state is saved in
`network_lockdown.json` in the state directory. If some actions cannot be
reverted, that file is kept and the failures are listed. NetworkManager may
bring interfaces back on its own; the optional `--with-firewall` drop table is
not affected by that.

## Starting over

`python3 -I -B airlock.py discard-session` archives the session record (under
`archive/`) and deletes its quarantine. The quarantine is on tmpfs by default
and disappears at reboot.

## Verifying on the Windows laptop

With minisign for Windows and the public key file you copied from Termux
yourself (never one from the USB):

```
minisign -Vm .\RECOVERY_TRANSFER\ORIGINAL_SIGNED_MANIFEST\manifest.json -p C:\path\to\signing.pub
Get-FileHash -Algorithm SHA256 .\RECOVERY_TRANSFER\FILES\*.ps1
```

Compare each hash with the `files` entries in the signed `manifest.json`.
`MANIFEST\SHA256SUMS.txt` is the MX forward manifest: useful, but MX is not
the source of trust.

Compare against hashes you recorded independently whenever possible. Read the
scripts before running them.
