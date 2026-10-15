# Rollback

Every modifying run takes a verified backup first, and prints the exact command
to undo itself.

## Undoing a run

```sh
# what backups exist?
secure-debian-bootstrap --list-backups

# preview the restore - changes nothing
sudo secure-debian-bootstrap --rollback 20260806T183055Z-00005a5b --dry-run

# perform it
sudo secure-debian-bootstrap --rollback 20260806T183055Z-00005a5b
```

The backup id is the run id of the run that created it, and it is printed in
that run's report under "how to undo this run".

## What rollback verifies before writing anything

Rollback is an attack surface: a forged manifest that restored files to
arbitrary paths would be a privilege escalation. Every restore therefore
re-validates from scratch.

1. **The backup exists and has `meta.json`.** A backup without identity
   metadata is refused.
2. **Checksums verify.** `manifest.sha256` is checked in full. A single
   mismatch aborts the restore — a tampered backup is never applied.
3. **Platform identity matches.** `meta.json` records platform, `os_id`,
   codename, architecture, and machine-id. A backup from a different platform or
   OS is refused outright and `--yes` cannot override it. A different codename or
   machine-id prompts for confirmation.
4. **Every manifest path is re-validated.** Absolute paths, `..` traversal,
   empty components, leading dashes, and embedded tabs/newlines are rejected
   (`sdb_manifest_path_is_safe`). This is tested directly in
   `tests/test-backup-layout.sh` with a manifest containing
   `../../../../etc/shadow`.
5. **Destinations must be inside the recorded root and inside the detected
   platform's write roots.** Anything else is skipped and reported.
6. **Symlinked destinations are not followed.** If the destination is currently
   a symlink pointing outside the write roots, the link is removed and the real
   object restored in its place.

## What is restored

| Property | Restored |
| --- | --- |
| File content | yes, atomically (temp file + rename) |
| Mode | yes |
| Ownership | yes when running as root or with usable sudo; warned otherwise |
| Modification time | yes, best effort |
| Symlinks | yes, as symlinks — the target is never dereferenced |
| Directories | yes, with their recorded mode |
| Extended attributes / ACLs | recorded in the backup; **not** re-applied automatically |

Entries outside the selected operation's roots are skipped and counted; the run
prints the skip count, and `rollback-report.txt` records the detail.

## After a rollback

The backup is **not** consumed or deleted — it can be restored again. The
rollback report names it explicitly.

Verify the result:

```sh
sudo apt-get update
```

## Undoing a quarantine

Quarantined files were renamed, not deleted. To restore them:

```sh
# they are listed with their new names in
cat /var/lib/secure-debian-bootstrap/quarantine/<run-id>/manifest.tsv
```

and can be moved back by hand, or with `sdb_quarantine_restore <run-id>` from a
shell that has sourced the libraries. Note that quarantined material was
flagged as high-severity for a reason — read the manifest's `reason` column
before restoring anything.

## Undoing baseline hardening

Hardening never edits vendor files. Every change is a separate drop-in file
named `60-secure-debian-bootstrap*`:

| Control | File | Undo |
| --- | --- | --- |
| `ssh_client_config` | `/etc/ssh/ssh_config.d/60-secure-debian-bootstrap.conf` | delete the file |
| `ssh_server_config` | `/etc/ssh/sshd_config.d/60-secure-debian-bootstrap.conf` | delete the file, then `systemctl reload ssh` |
| `core_dumps` | `/etc/security/limits.d/60-secure-debian-bootstrap-coredump.conf` | delete the file |
| `file_permissions` | (mode changes under the APT root) | `--rollback <backup-id>` |

Every other hardening control is report-only and changes nothing.

## Limits of assurance

Rollback restores the APT configuration this tool backed up. It does not, and
cannot:

- undo package installations or removals performed by apt itself
- recover from a compromise that reached the kernel, initramfs, or firmware
- prove that a system which was compromised before the backup was taken is now
  clean — the backup may faithfully preserve the attacker's configuration,
  which is why the audit findings matter more than the backup does

If the audit shows that trust anchors were replaced by an adversary with root,
the only sound recovery is reinstallation from verified media. The tool says so
in its report rather than implying otherwise.
