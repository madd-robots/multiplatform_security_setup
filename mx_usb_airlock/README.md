# MX USB Transfer Airlock (V1.1)

A defensive integrity-transfer system that moves an approved PowerShell
security package through removable media:

```
Trusted Android/Termux  --(signed + encrypted package)-->  transport USB
  --> potentially compromised MX Linux: read-only ingest, authenticate, decrypt,
      verify, sealed staging
  --> transport USB physically removed
  --> separate clean USB: written from verified staging, whole filesystem verified
  --> clean Windows computer
```

> **Read [SECURITY_MODEL.md](SECURITY_MODEL.md) first.** The MX host is
> treated as potentially compromised. Software running under a kernel that an
> attacker fully controls cannot establish an absolute boundary against that
> kernel. The system provides layered defences:
> - external source authentication (signed manifest)
> - encryption in transport, with signing and encryption keys kept separate
> - read-only ingress
> - strict allowlisting
> - repeated hashing
> - device identity checks
> - physical separation of the incoming and outgoing media
> - sealed staging
> - whole-destination verification and post-write re-reading
> - fail-closed state transitions
>
> The preferred workflow runs the MX side from verified live media.

Nothing from any USB is ever executed. PowerShell files are data while on MX.

## Keys: what lives where

| Key | Where it lives | Never goes to |
|---|---|---|
| Signing **secret** key (minisign Ed25519) | Termux only: `~/.usb_airlock/signing.key` | transport USB, MX, clean USB, Windows, repository, logs |
| Signing **public** key | Termux; **pinned** on MX in `~/.config/mx_usb_airlock/keys/` | (public; pinned by typed fingerprint) |
| Transport **identity** (age X25519 secret) | MX only: `~/.config/mx_usb_airlock/keys/transport_identity.age` | transport USB, Termux, clean USB, Windows, logs |
| Transport **recipient** (age public) | MX; copied to Termux `~/.usb_airlock/mx_recipient.txt` | (public) |

The transport USB carries ciphertext, the signed manifest and its signature.
It never carries a secret. On live media without persistence, keep the MX key
directory on the trusted live medium or on other trusted storage
(`--keys-dir`), never on the transport USB; MX refuses that location.

## Dependencies (minimum; nothing is upgraded)

| Package | Side | Why |
|---|---|---|
| `python` (3.9+) | Termux | runs `usb_airlock_prepare.py` |
| `minisign` | Termux | creates the signing key and signs the manifest |
| `age` | Termux | encrypts the payload to the MX recipient |
| `python3` (3.9+), `util-linux`, `mount`, `sudo` | MX | the airlock itself (V1.0 requirements) |
| `minisign` | MX | verifies the manifest signature |
| `age` (provides `age-keygen`) | MX | creates the transport identity and decrypts |

Termux: `pkg install python minisign age`. MX/Debian:
`sudo apt install minisign age`. Install only these packages; no upgrade is
needed. Optional MX tools (`udevadm`, `ip`, `rfkill`, `nft`, `clamscan`,
`wipefs`, `sfdisk`, `mkfs.vfat`) are unchanged from V1.0. Once installed,
preparation, ingest and release work entirely offline. Nothing (keys,
manifests, packages, configuration) is fetched from a network.

## Installing the release bundle on MX

A release publishes **two different hashes**. Do not mix them up:

| Value | Published in | What it covers | Where you use it |
|---|---|---|---|
| **Archive SHA-256** | `mx_usb_airlock-1.1.0.tar.gz.sha256` | the `.tar.gz` file itself | `sha256sum -c` before extracting |
| **Bundle digest** | `mx_usb_airlock-1.1.0.SHA256SUMS.sha256` | the `SHA256SUMS` file inside the archive | `install.sh --expect-digest` |

`install.sh --expect-digest` only accepts the **bundle digest**. Passing the
archive SHA-256 there always fails.

1. On a trusted machine, record **both** values somewhere other than the USB
   drive you carry the bundle on (for example on paper, or from the
   GitHub release or commit).
2. Check the archive against the recorded **archive SHA-256**:
   `sha256sum -c mx_usb_airlock-1.1.0.tar.gz.sha256`, and confirm the value
   printed in that file is the one you recorded.
3. On the live system, extract the archive and install with the recorded
   **bundle digest**:
   ```
   tar -xzf mx_usb_airlock-1.1.0.tar.gz
   cd mx_usb_airlock-1.1.0
   sudo ./install.sh --expect-digest <BUNDLE DIGEST from mx_usb_airlock-1.1.0.SHA256SUMS.sha256>
   ```
   The installer:
   - checks every file against `SHA256SUMS` and accepts only the expected
     file list
   - checks the bundle digest (the SHA-256 of `SHA256SUMS`) against `--expect-digest`
   - checks Python 3.9+, the required tools, and the authenticated-mode tools
     (it only reports missing ones and installs nothing)
   - runs the bundled test suite (simulation only)
   - installs into a staging directory, re-verifies it, and swaps it into
     `/opt/mx_usb_airlock`
   - writes the launcher `/usr/local/bin/mx-usb-airlock`, which runs
     `python3 -I -B .../airlock.py`
4. Run `mx-usb-airlock status`.

Installer options: `--check-only` (verify and test, change nothing),
`--uninstall`, `--prefix DIR` / `--bin-dir DIR`, `--skip-tests`, `--yes`.
Without `sudo` it installs into `~/.local/share/mx_usb_airlock` and
`~/.local/bin` (works, but the files are then writable by your account).

## Installing the Termux application

Copy `termux/usb_airlock_prepare.py` from the verified bundle onto the
Android device, for example into `~/usb_airlock/` in Termux. Then:

```
pkg install python minisign age
python ~/usb_airlock/usb_airlock_prepare.py --help
```

It needs no root and no network.

## Complete operator workflow

**One-time key setup**

1. **Termux, initialise the signing key** (choose a password when asked):
   `python usb_airlock_prepare.py init-keys`
   Note the key ID and the **SHA-256 fingerprint** it prints.
2. **MX, create the transport identity:**
   `mx-usb-airlock init-transport-key`
   It prints a recipient (`age1...`). That value is public.
   **Termux, store it:**
   `python usb_airlock_prepare.py set-recipient age1...`
   **MX, pin the Termux signing public key:**
   `mx-usb-airlock trust-signing-key --public-key-string <base64 line from show-keys>`
   (or `--public-key FILE`). Type the first five fingerprint groups exactly
   as Termux `show-keys` displays them. Replacing a pinned key later requires
   `--replace` and a typed confirmation.

**Each transfer**

3. **Termux, prepare** the approved files from a dedicated folder or an
   explicit list:
   `python usb_airlock_prepare.py prepare --source-dir ~/approved --output ~/airlock_out`
   or `... prepare --files a.ps1 b.ps1 --base ~/approved --output ~/airlock_out`
4. This creates `~/airlock_out/AIRLOCK_TRANSFER/`, signed and encrypted, and
   self-verifies it (`... verify ~/airlock_out/AIRLOCK_TRANSFER` repeats the
   check).
5. Copy the `AIRLOCK_TRANSFER` directory to the root of the transport USB
   (Android file manager, or `termux-setup-storage` and `cp -r`). Copy
   nothing else.
6. **MX** (preferably verified live media, offline):
   `mx-usb-airlock network-lockdown` (optional), `mx-usb-airlock status`,
   then `mx-usb-airlock ingest`.
7. Insert **only** the transport USB when asked, and confirm its identity
   (`YES`).
8. Quarantine: the block device is set read-only and verified, the
   filesystem is mounted `ro,nodev,nosuid,noexec` and verified, and the
   package is copied into private staging.
9. Authenticate: the signature is checked with the pinned key, the manifest
   strictly, and the payload SHA-256.
10. Decrypt: age, unprivileged, to memory.
11. Verify the staged files: exact names, count, sizes, SHA-256 and types, and
    the content policy. Staging is sealed.
12. When **REMOVE DIRTY USB NOW** appears, unplug the transport USB and type
    `REMOVED`. Absence is verified.
13. `mx-usb-airlock review`: read the findings, then type `APPROVE` to approve
    the complete signed set.
14. `mx-usb-airlock release`, then insert the **clean** USB when asked and
    type `WRITE` plus the last 4 serial characters. It must be empty (prepare
    a drive with `mx-usb-airlock prepare-clean-usb`, which erases it after an
    `ERASE <serial tail>` confirmation).
15. Staging, manifest and signature are re-verified immediately before the
    write.
16. Export: only verified staging is written, together with the original
    signed manifest and signature, and the MX forward manifest and report.
17. Whole-filesystem verification after a sync, unmount, buffer flush and
    read-only remount: nothing may exist besides the expected files.
18. Post-write hash verification: every file is re-read from the device.
19. When **REMOVE CLEAN USB NOW** appears, unplug it. Optional:
    `mx-usb-airlock verify-clean` re-checks it later, including the signed
    manifest.
20. Take the clean USB to the Windows computer. Verify
    `ORIGINAL_SIGNED_MANIFEST/manifest.json` with minisign and the public key
    you copied from Termux yourself, then compare the file hashes (see
    [RECOVERY.md](RECOVERY.md)).

## MX commands

| Command | Purpose |
|---|---|
| `status` | Environment, live media, network, devices, session phase, mode, gates (read-only) |
| `ingest` | Authenticated ingest of a signed `AIRLOCK_TRANSFER/` package (default) |
| `ingest --legacy` | V1.0 **unauthenticated** mode: allowlisted plain files, trust only via optional `--trusted-hashes` |
| `review` | Show findings; authenticated mode approves the complete signed set |
| `release` | Clean-destination policy, pre-export re-verification, write, whole-filesystem verification |
| `verify-clean` | Re-verify a clean USB read-only (whole filesystem, local inventory, signed manifest) |
| `prepare-clean-usb` | **Destructive**: erase one USB and create one FAT32 partition |
| `init-transport-key [--replace]` | Create the MX age identity and print its recipient |
| `trust-signing-key --public-key FILE \| --public-key-string B64 [--replace]` | Pin the Termux signing public key (typed fingerprint) |
| `show-keys` | Show the pinned key fingerprint and the transport recipient |
| `report`, `network-lockdown`, `network-restore`, `discard-session` | As in V1.0 (the lockdown now fails closed unless verified offline) |

Global options: `--state-dir`, `--keys-dir`, `--config FILE`,
`--live-device /dev/disk/by-id/...`, `--simulate SCENARIO.json`. Exit codes:
`0` success, `1` BLOCKING, `2` cancelled, `3` configuration or missing tool.

There is no option to skip signature, hash or decryption checks, and no
override for missing block-layer read-only protection.

## Termux commands

| Command | Purpose |
|---|---|
| `init-keys [--no-password]` | Create the signing key pair once (never overwrites) |
| `set-recipient age1... [--replace]` | Store the MX transport recipient |
| `show-keys` | Key ID, fingerprint, public key line, recipient |
| `prepare (--source-dir DIR \| --files F... [--base DIR]) --output DIR` | Build and self-verify `AIRLOCK_TRANSFER/` |
| `verify PACKAGE_DIR` | Re-check a package's signature and payload hash |

Input is refused for any of these:
- symlinks, FIFOs, sockets, device nodes and hard-linked files
- `..` traversal, and paths outside the selected root
- duplicate paths, including names that differ only in case
- malformed names (control and bidi characters, Windows-invalid or reserved
  names, trailing dots or spaces, and non-ASCII by default, the same policy
  as MX)
- types outside the allowlist, NUL-containing files, and oversized files
- broad locations such as `~` or `/sdcard`

## Clean USB layout

```
RECOVERY_TRANSFER/
  FILES/                              the signed files, original relative paths
  ORIGINAL_SIGNED_MANIFEST/manifest.json      the ORIGINAL trusted manifest (from Termux)
  ORIGINAL_SIGNED_MANIFEST/manifest.minisig   its signature
  ORIGINAL_SIGNED_MANIFEST/SIGNING_KEY.txt    key ID and fingerprint (for comparison only)
  MANIFEST/SHA256SUMS.txt             MX FORWARD integrity manifest (MX is not the source of trust)
  MANIFEST/manifest.json              MX forward manifest (kind MX_FORWARD_INTEGRITY_MANIFEST)
  REPORTS/transfer-report.txt|json
```

Nothing else may exist anywhere on the clean USB.

## Upgrading from V1.0.0

1. Install the 1.1.0 bundle as above. The installer replaces the managed
   `/opt/mx_usb_airlock` and its launcher. Configuration files remain valid
   (one new optional key, `max_transfer_payload_bytes`). Logs, reports and
   archived sessions in the state directory are kept.
2. Set up keys (workflow steps 1-2). Nothing is created automatically, and no
   trusted key is ever fabricated on MX.
3. A V1.0.0 session that is still open is refused with `SESSION_FROM_V1_0`.
   Finish it with V1.0.0, or start over with `ingest --new-session`.
4. Behaviour changes:
   - plain ingest now requires a signed package; the V1.0 flow is
     `ingest --legacy`
   - the `PROCEED` read-only override is gone
   - a non-empty clean USB is refused instead of warned about
   - staging is sealed read-only

## Messages

`[PASS]`, `[WARNING]`, `[BLOCKING]` and `[INFO]` prefix every result. The tool
never declares a file "safe". It reports specific facts, for example:
*SIGNED MANIFEST VERIFIED*, *ENCRYPTED PAYLOAD MATCHES THE SIGNED MANIFEST*,
*DECRYPTED FILES MATCH THE SIGNED MANIFEST EXACTLY*, *SOURCE MOUNTED
READ-ONLY*, *DESTINATION HASH MATCH VERIFIED*, *WHOLE DESTINATION FILESYSTEM
VERIFIED*.

## Files

- `airlock.py`: the MX application (single file, standard library only)
- `termux/usb_airlock_prepare.py`: the Termux preparation application
- `config.example.json`: inert configuration example
- `SECURITY_MODEL.md` (security and threat model), `RECOVERY.md`, `TESTING.md`
- `install.sh`, `tools/make_bundle.py`
- `tests/`: simulation tests, installer tests, V1.1 tests, and a gated
  destructive integration test
