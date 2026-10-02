# Security model

## The most important limitation

**Running this application inside a compromised operating system cannot
establish a trustworthy clean boundary against an attacker controlling that
OS or kernel.** Such an attacker can change what the tool sees, what it
writes, what it hashes and what it reports. No user-space program can detect
or prevent that reliably.

**The preferred workflow is a verified live Linux environment.** Boot a
known-good MX Linux, Debian or compatible live image from separately prepared
trusted media, verify that media against a published hash when one is
available, keep networking disabled, do not mount the laptop's internal
Windows or Linux partitions, and run the airlock from that live session.

The tool still runs on an installed MX Linux system, because sometimes that is
all there is. In that case it prints and records a warning that this cannot
provide the same trust level as verified live media.

## V1.1 trust chain (threat model)

The route is: trusted Android/Termux -> transport USB -> **potentially
compromised** MX Linux -> sealed staging -> separate clean USB -> clean
Windows computer. The goal is to make it as difficult as reasonably practical
for unauthorized files or modifications from the MX host to travel forward.
It cannot be made impossible: see the limitation above.

| Mechanism | What it establishes | What it does NOT establish |
|---|---|---|
| **minisign (Ed25519) signature** over `manifest.json`, made on Termux | **Authenticity**: the transfer set (paths, sizes, SHA-256, types, and the encrypted payload's SHA-256) was approved by the holder of the Termux signing key. This is the root of trust. | Anything about the MX host. |
| **SHA-256** | **Integrity comparison** against the signed values: payload before decryption, every decrypted file, staging before export, destination after the write. | Origin, unless compared with a signed or independently trusted value. |
| **age (X25519) encryption** to the MX transport recipient | **Confidentiality on the transport medium**: a lost, copied or intercepted transport USB reveals no plaintext. | Authenticity: encryption alone never vouches for the sender. It also gives no confidentiality against the MX host, which must decrypt in order to verify and stage. |

**Key placement (how separation is maintained):**

| Key | Created on | Stored | Never copied to |
|---|---|---|---|
| Signing **secret** key (minisign) | Termux (`init-keys`), password-protected by default | Termux `~/.usb_airlock/signing.key` (0600) | transport USB, MX, clean USB, Windows, repository, logs |
| Signing **public** key | Termux | MX `~/.config/mx_usb_airlock/keys/trusted_signing_key.pub`, pinned by `trust-signing-key` after the operator types the first 80 bits of its SHA-256 fingerprint as shown on Termux | (public; the fingerprint, not the minisign key ID, is the identity: key IDs are random bytes that anyone can copy into another key) |
| Transport **identity** (age secret) | MX (`init-transport-key`) | MX `~/.config/mx_usb_airlock/keys/transport_identity.age` (0600) | transport USB, Termux, clean USB, Windows, logs |
| Transport **recipient** (age public) | MX | Termux `~/.usb_airlock/mx_recipient.txt` | (public) |

Signing and encryption keys are separate key pairs held by different
machines. The transport USB carries ciphertext, the signed manifest and the
signature, never a secret. MX refuses a key directory located on attached
removable media. Replacing either MX key needs `--replace` plus a typed
confirmation phrase; the old key is kept as `retired-*`. Nothing is fetched
from a network: keys are local and pinned.

**MX gate order (authenticated mode, enforced by an ordered gate list; any
out-of-order transition is `ILLEGAL_TRANSITION`):**

`INCOMING_QUARANTINED` (device identified, block-layer and mount read-only
verified, package copied into private staging) -> `SIGNED_MANIFEST_VERIFIED`
(minisign with the pinned key over the raw bytes, then strict parsing, and a
trusted comment binding the transfer ID and the manifest SHA-256) ->
`ENCRYPTED_PAYLOAD_VERIFIED` -> `PAYLOAD_DECRYPTED` (age, unprivileged, from
the verified in-memory bytes through stdin to memory: no ciphertext re-read
and no plaintext temporary file) -> `DECRYPTED_FILES_VERIFIED` (tar members
enumerated and validated, never extracted by tarfile; exact names, count,
sizes, SHA-256 and types, plus the V1.0 content checks) -> `STAGING_SEALED`
(0500 directory, 0400 files) -> `INCOMING_REMOVED` ->
`DESTINATION_VERIFIED_EMPTY_OR_PREPARED` -> `PRE_EXPORT_REVERIFIED` (every
staged SHA-256, the staged manifest and the signature re-checked with the
pinned key immediately before writing) -> `EXPORTED` ->
`DESTINATION_WHOLE_FS_VERIFIED` -> `COMPLETE`. There is no option to skip
signature, hash or decryption checks.

**Whole-destination verification.** Before writing, the entire mounted clean
filesystem must be empty apart from documented metadata, otherwise
`DESTINATION_NOT_CLEAN` (nothing is written or deleted). After writing,
syncing, unmounting, flushing and remounting read-only, the entire filesystem
is enumerated again. Every expected file is re-read and re-hashed from the
device. Anything else anywhere (root files, `autorun.inf`, `.lnk`,
executables, hidden files, extra directories, extra files inside the transfer
directory) is `DESTINATION_CONTAMINATION`, and the transfer is not marked
complete. The metadata allowlist (`DEST_METADATA_ALLOWLIST`) is **empty** for
vfat and exfat: `mkfs.vfat`/`mkfs.exfat` leave no entries that Linux lists
(the FAT volume label and the exFAT bitmap/upcase entries are not returned by
readdir). Windows creates `System Volume Information` only after the drive
has been attached to Windows; such a drive is not freshly prepared and is
refused.

**Forward package.** The clean USB carries the ORIGINAL signed manifest and
signature (`ORIGINAL_SIGNED_MANIFEST/`) plus the key ID and fingerprint, kept
separate from the MX-generated `MANIFEST/` (the MX forward integrity
manifest). MX is never the source of trust because it computed fresh hashes.
On Windows, verify `ORIGINAL_SIGNED_MANIFEST/manifest.json` with minisign and
the public key you obtained from Termux, never with a key that came on the
USB.

**Legacy mode.** `ingest --legacy` keeps the V1.0 unauthenticated workflow
(allowlisted plain files, trust only through optional operator hashes). It is
never selected automatically: an authenticated package found in legacy mode,
or no package in authenticated mode, stops the ingest. Legacy mode is not
equivalent in trust to the signed-manifest path.

## What is protected, and how

| Threat | Control |
|---|---|
| Malicious files executed during transfer | Nothing from either drive is executed, sourced, imported or opened by another program. Mounts use `nodev,nosuid,noexec`. PowerShell files are treated purely as data. |
| Writes to the dirty drive | `blockdev --setro` on the whole disk and every partition, verified through `blockdev --getro` and sysfs. Read-only mount. ext3/ext4 are mounted with `noload` so a journal is never replayed. `mount -i` prevents filesystem helper programs from running. If block-layer read-only cannot be established and verified, ingest **stops** (V1.1 removed the V1.0 `PROCEED` override). It is re-checked in sysfs after mounting and after reading; losing it is `BLOCK_READONLY_LOST`. The mount must show `ro,nodev,nosuid,noexec` per mount, and `ro` in the kernel's superblock flags. |
| Desktop automount | Existing mounts are detected and unmounted, and the event is recorded. A read-write automount of the dirty drive stops normal processing until you type `CONTINUE`. Before every mount the tool re-checks for a concurrent remount and stops if it finds one. Desktop settings are never changed. |
| Dirty and clean drives attached together | Enforced state machine: more than one removable storage device means STOP. Ingest ends with physical removal, confirmed by re-enumeration. Review and release refuse to run until no removable storage is attached. Every identity revalidation (before mounting and before each write) also fails if any other removable disk is attached, including one hidden as "in use" because it is mounted somewhere such as `/mnt`. Removal checks compare the dirty drive's fingerprint against every removable disk before any protection filtering. Release refuses any device already attached before its insertion prompt, and any device matching the dirty drive's serial, by-id path, filesystem UUID, or model+vendor+size when serials are missing. |
| Writing to the wrong device | Devices are identified by serial, model, vendor, size, `/dev/disk/by-id` and major:minor, never by `/dev/sdX` alone. The full identity is shown before any write. The destination must report a serial number, and you must type `WRITE <last 4 serial characters>`. Identity is re-checked before mounting and before **every** file write. Read-only destinations are refused because they may be the dirty drive. |
| System or live disk selected | Disks backing `/`, `/boot`, `/home`, `/usr`, `/var`, swap, live-media mounts (`/live`, `/run/live`, ...), loop-image backing files and kernel command-line boot UUIDs are protected. So is any disk mounted outside desktop automount locations, and anything named with `--live-device` (a partition link such as `...-part1` protects its whole disk). Protected disks are never offered. Internal (non-hotplug) disks are never offered. |
| Malicious filenames | Rejected: traversal, slashes, backslashes, control characters, newlines, bidi overrides, zero-width/format characters, non-NFC names, all non-ASCII names by default (lookalike defence), characters Windows rejects, trailing dots or spaces, reserved device names, overlong names, deceptive double extensions (`x.exe.txt`), and case-insensitive collisions, including directories that differ only in case (`A/` and `a/`). Names are always displayed escaped. |
| Symlinks, hardlinks, special files, mount escapes | The tree is walked with directory file descriptors and `O_NOFOLLOW`. Symlinks are rejected and never followed. Device nodes, FIFOs and sockets stop the ingest. Crossing a filesystem boundary stops the ingest. Files are re-checked by inode after opening. Ownership, modes, ACLs, xattrs, capabilities and setuid bits are never copied: every output is a new regular file. |
| Disguised binaries | Only allowlisted extensions are accepted. Executables, other interpreters' scripts, archives, images and Office formats are on a deny list that configuration cannot override. Content signatures (PE, ELF, Mach-O, ZIP/Office, OLE/MSI, archives, disk images, PDF, RTF, LNK, ...) are rejected whatever the extension. Text must be valid UTF-8, UTF-16 with BOM, or Windows-1252 (flagged). NUL bytes and binary control content are rejected. |
| Suspicious PowerShell | Static **review flags** (informational, never automatic rejection or rewriting): encoded commands, Base64 decoding, Invoke-Expression/IEX, downloads (WebClient, Invoke-WebRequest, curl/wget, BITS, certutil), reflection/Add-Type, rundll32/regsvr32/mshta, scheduled tasks, services, Run keys, WMI persistence, remoting/WinRM, Defender exclusions/disabling, firewall disabling, execution-policy weakening, hidden windows, escape-character keyword splitting, long lines, Base64 blobs, high-entropy tokens, bidi/invisible Unicode. Hardening scripts legitimately trigger many of these. |
| Tampering between stages | Quarantine is a private directory, tmpfs by default, with opaque file names and files created with `O_EXCL`. After verification it is sealed (0500 directory, 0400 files). Approval is bound to the SHA-256. Release re-reads and re-hashes every staged file before the destination is inserted and again immediately before writing; any change blocks the session. |
| Hash claims | A mismatch against an operator-supplied trusted SHA-256 is **blocking** and sticky. Files without one are marked `HASH_NOT_PREAUTHORIZED`, and approving them requires typing `APPROVE`. Hash lists found on the dirty drive are untrusted metadata: they are compared for information only and can never raise trust. A trusted hash file on removable media, or inside the quarantine, is refused. |
| Silent write corruption | After writing: `fsync` per file, directory fsync, `sync`, unmount, `blockdev --flushbufs` (a failed or unavailable flush blocks the verification claim), then a fresh **read-only** remount and re-hash of every written file, with a check for missing or extra files. Any difference is blocking. |
| Network exfiltration or download | The transfer needs no network. Optional `--offline-lockdown` / `network-lockdown` saves prior state, then soft-blocks radios, downs interfaces and optionally adds an nftables drop table. The lockdown fails closed unless the result is verified offline (state known, no interface up, no default route, no failed step). `network-restore` reverts only what was changed. ClamAV signatures are never updated by the tool. |
| Injection into commands | No shell is ever used. Commands run as fixed argument arrays from root-owned system directories (never from `PATH`), with a minimal environment, timeouts and checked exit status. Privileged arguments are validated device nodes (major:minor re-checked) and the tool's own private mount points. |
| Hostile terminal output | Labels, models, serials, filenames and tool stderr are escaped to printable ASCII before display or logging. |
| Logs leaking content | Per-run append-only JSON-lines logs contain names, hashes, sizes and decisions. They never contain file contents or passwords. |

## Residual risks (not solved by this tool)

- **The MX host sees plaintext.** It must decrypt in order to verify and
  stage, so a compromised MX kernel can read, and in principle alter, what it
  forwards. The signed manifest travels forward so the final recipient can
  check it independently with the pinned public key.
- **The MX transport identity lives on MX.** Whoever controls MX can decrypt
  future packages addressed to it. Rotate it with `init-transport-key
  --replace` if MX was compromised.
- **The Termux device is the root of trust.** If it, or the signing key and
  its password, is compromised, malicious packages verify correctly.

- **Kernel filesystem parsing.** Mounting a crafted filesystem exercises the
  kernel's filesystem driver, even read-only. A kernel bug could be exploited
  at mount time. Using a fresh live session that you discard afterwards limits
  persistence.
- **USB firmware attacks ("BadUSB").** A device can pretend to be a keyboard
  or network adapter, or lie about its serial number. Identity checks raise
  the bar but cannot defeat a device that spoofs another one perfectly. Use
  physically distinct, labelled drives, and watch for unexpected input
  devices.
- **Device-level caching.** Re-hashing after a remount defeats the Linux page
  cache, but cannot prove that the USB controller's own cache matches the
  flash. `verify-clean` after re-plugging the drive gives additional
  assurance.
- **Same-user attackers.** Anything running as your user (or with your cached
  `sudo` credentials) can alter the state directory, quarantine or session
  file. This is one more reason to use a fresh live session.
- **ClamAV and static flags are heuristics.** "No detection" and "no flags"
  are not evidence that a file is benign. Your own review of the PowerShell
  content and independently trusted hashes are what establish trust.
- **A self-generated hash proves nothing about origin.** It only identifies
  the bytes you approved, so that later corruption can be detected.
- **Out of scope:** ext/NTFS sources owned by other users may be unreadable as
  a normal user (reported as `PERMISSION_DENIED`). UTF-16 files without a BOM
  are rejected. Destinations must be FAT32 or exFAT.

## Fail-closed conditions

The tool stops (exit code 1) on: system or live disk selected; multiple
removable devices during a stage; destination matching the source; identity
changes of source or destination; a device disappearing; a filesystem
unmounted unexpectedly; impossible names (traversal); special files;
filesystem boundary crossings; source read errors; failed unmount; failed
mount or missing mount options; trusted-hash mismatch; quarantine tampering;
destination verification mismatch; ambiguous selection; insecure state
directory; and any unexpected internal error.

These are reported but do not stop the run: ClamAV unavailable, static review
flags, quarantine not on tmpfs, source without a serial number (an extra
confirmation is required), and non-ASCII content.
