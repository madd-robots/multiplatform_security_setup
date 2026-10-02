# MX USB Transfer Airlock

A defensive tool for MX Linux (and other Debian-based live systems). It moves a
small set of text-based recovery files, such as PowerShell hardening scripts,
from an **untrusted ("dirty") USB drive** through a local quarantine onto a
**clean USB drive**. The two drives are never attached during the same stage.

```
DIRTY USB -> READ-ONLY INGEST -> LOCAL QUARANTINE -> DIRTY USB PHYSICALLY REMOVED
-> VALIDATION -> CLEAN USB INSERTED -> CONTROLLED WRITE -> FINAL VERIFICATION -> CLEAN USB REMOVED
```

> **Read [SECURITY_MODEL.md](SECURITY_MODEL.md) first.** Running inside a
> compromised operating system cannot establish a trustworthy clean boundary.
> The preferred workflow uses a verified live Linux environment.

This is not a general USB copier. By default it only accepts `.ps1 .txt .md
.json .sha256 .sha256sum .csv` files that pass content checks. Nothing from
either drive is ever executed.

## Requirements

- Linux with Python 3.9+ (standard library only), `util-linux` (`lsblk`,
  `mount`, `umount`, `blockdev`) and `sudo` or a root shell for the mount steps.
- Optional: `udevadm`, `ip`, `rfkill`, `nft` (offline lockdown), `clamscan`
  (signature scan, never updated by this tool), `wipefs`, `sfdisk`,
  `mkfs.vfat` (only for `prepare-clean-usb`).
- Clean USB drive with FAT32 or exFAT that reports a serial number.

Nothing is installed, and no services, cron jobs, udev rules or desktop
settings are created or changed.

## Operational workflow (exact steps)

Run every command from the directory holding `airlock.py`, as a normal user
(the tool calls `sudo` only for block-device, mount and network steps).
`python3 -I -B` makes Python ignore environment variables and user paths.

1. Boot a verified live Linux from separately prepared trusted media. Keep
   networking off. Do not mount the laptop's internal drives. Copy
   `airlock.py` from trusted media and check its SHA-256 against a value you
   recorded earlier.
2. Disable desktop automount if you can (see [RECOVERY.md](RECOVERY.md)).
3. Optional: `python3 -I -B airlock.py network-lockdown`
4. `python3 -I -B airlock.py status`
5. Insert **only the dirty USB**. Then run:
   `python3 -I -B airlock.py ingest --trusted-hashes ~/trusted_hashes.txt`
   (leave out `--trusted-hashes` if you have no independently known hashes).
   Confirm the device identity by typing `YES`.
6. When it shows **REMOVE DIRTY USB NOW**, physically unplug it and type `REMOVED`.
   The tool checks that it is gone.
7. `python3 -I -B airlock.py review`. Approve each file. A file without a
   trusted hash needs you to type `APPROVE` as well.
8. `python3 -I -B airlock.py release`. Insert the **clean USB** only when asked,
   then type `WRITE` plus the last 4 characters of its serial number.
9. Wait for **DESTINATION HASH MATCH VERIFIED** and **REMOVE CLEAN USB NOW**,
   then unplug it.
10. Optional: `python3 -I -B airlock.py report`, `verify-clean`, `network-restore`.

## Commands

| Command | Purpose |
|---|---|
| `status` | Environment, live-media detection, network state, devices, session phase (read-only) |
| `ingest` | Phase A: identify dirty USB, set it read-only, mount `ro,nodev,nosuid,noexec`, filter, inspect, hash, quarantine, unmount, require physical removal |
| `review` | Show findings and hashes; apply trusted hashes; approve files |
| `release` | Phase B: re-verify quarantine, identify clean USB, write approved files, unmount, remount read-only, re-hash |
| `verify-clean` | Re-verify a clean USB read-only against the local session and its own manifest |
| `prepare-clean-usb` | **Destructive and optional.** Erase one USB drive and create one FAT32 partition (you must type `ERASE` plus the serial tail) |
| `report` | Print and save text and JSON reports |
| `network-lockdown` / `network-restore` | Reversible offline mode (rfkill, links down, optional nftables drop with `--with-firewall`) |
| `discard-session` | Archive the session and delete its quarantine |

Global options: `--state-dir`, `--config FILE` (see `config.example.json`),
`--live-device /dev/disk/by-id/...` (marks live media that was not detected
automatically, so it can never be selected), `--simulate SCENARIO.json`
(practice mode, see [TESTING.md](TESTING.md)).

Exit codes: `0` success, `1` BLOCKING (stopped, fail-closed), `2` cancelled,
`3` configuration or missing tool.

## Clean USB layout

```
RECOVERY_TRANSFER/            (RECOVERY_TRANSFER_<run-id> if that name exists)
  FILES/                      approved files only, original relative paths
  MANIFEST/SHA256SUMS.txt     sha256sum format
  MANIFEST/manifest.json      names, sizes, SHA-256/512, hash status, review flags
  REPORTS/transfer-report.txt
  REPORTS/transfer-report.json
```

On Windows, check a file with
`Get-FileHash -Algorithm SHA256 .\RECOVERY_TRANSFER\FILES\<name>.ps1` and
compare it with `SHA256SUMS.txt`. Remember that the manifest is only as
trustworthy as the USB it is on. Compare against a hash you recorded
independently where possible.

## Messages

`[PASS]`, `[WARNING]`, `[BLOCKING]` and `[INFO]` prefix every result. The tool
never declares a file "safe". It reports specific facts instead: *SOURCE
MOUNTED READ-ONLY*, *INTEGRITY VERIFIED AGAINST TRUSTED HASH*, *NO TRUSTED
SOURCE HASH AVAILABLE*, *STATIC REVIEW FLAGS PRESENT*, *DESTINATION HASH MATCH
VERIFIED*.

## Files

- `airlock.py`: the application (single file, standard library only)
- `config.example.json`: inert configuration example
- `SECURITY_MODEL.md`, `RECOVERY.md`, `TESTING.md`
- `tests/`: simulation tests and a gated destructive integration test
