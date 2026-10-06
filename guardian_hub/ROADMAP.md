# Roadmap

This file follows the stage order of the Guardian build guide (v1.0) and
records where the implementation deviates from it and why.

## Stage status

| Stage | Scope | Status |
|---|---|---|
| 1 Foundation | common library, errors, canonical serialization, safe filenames, logging, tests | **Done** (`usbguardian/common`) |
| 2 Security runtime | privilege separation, broker, worker isolation, IPC, authorization | **Done**, with the hardening listed below still open (`usbguardian/runtime`) |
| 3 Device engine | USB detection, storage identity, vendor and controller data, capacity verification | **Done** (`usbguardian/devices`); see notes below |
| 4 Integrity vault (D1, D6) | custody object store, transfer package format, read-back verification, verify-then-release | **Done** (`usbguardian/vault`); see notes below |
| 5 YubiKey integration | enrollment, authentication, owner verification; manifest signer/verifier, revocation (D3); key rotation and locking; broker vault/transfer operations with fd passing | **Done** (`usbguardian/identity`, `vault/operations.py`); hardware validation pending, see notes |
| 6 Guardian Forge | spinoff packages, signing, encryption | Not started |
| 7 Platforms | Debian/MX, then Termux, then Windows | Not started |
| 8 Device assurance | firmware and artifact verification, erase verification, reports | Not started |
| 9 Final UI | dashboard, managers, forge, audit viewer | Not started |

### Stage 2 hardening still open

These were left out on purpose: each needs testing on the target MX kernel
before anything can rely on it, and none was claimed as done.

- seccomp-bpf syscall filter for workers
- Landlock filesystem restriction, so workers can read only the paths a job needs
- network namespace (or seccomp socket denial), so parser workers have no network
- the dedicated worker account, SysVinit service and root-owned install
  location (Stage 7 packaging)

### Stage 3 notes

- Enumeration reads sysfs and mountinfo directly inside the sandboxed
  worker. No tools are run, because workers cannot fork.
- Reports include USB descriptors and every interface, the SCSI INQUIRY
  strings, the MMC CID, capacity, block sizes, partitions, holders and
  mounts. "Controller information" means what the device exposes through
  those standard interfaces; there is no vendor-tool access (D4).
- Findings implement D4 step 1 at detection time: exactly one mass-storage
  interface (bulk-only or UAS), a single configuration, and no HID, network,
  serial or vendor interfaces. Internal, system, mounted or held disks are
  BLOCKING.
- The identity fingerprint (domain `guardian/device-identity/v1`) excludes
  volatile state, so any change in presented identity is detected.
- `device.surface_test` implements D4 step 2 (keyed full-surface write,
  O_DIRECT read-back, capacity proof). It is bound to the fingerprint the
  owner approved and cross-checked against kernel-side facts read by the
  broker. It opens the device with O_EXCL, re-checks identity afterwards,
  and needs `owner_key`, so it stays unreachable until Stage 5. It has been
  tested only on files and in-memory fakes, and must be validated on real
  sticks on MX before release.
- Left for later stages, because the code that needs them lives there:
  - kernel-level interface blocking before driver binding
    (`authorized_default=0` / usbguard) is a host configuration change and
    belongs to Stage 7 install
  - layout rebuild and signed whole-volume verification (D4 steps 3–5) are
    defined by the transfer format and belong to Stage 4
  - the surface test runs in the broker's connection thread and is not
    cancelled if the client disconnects; Stage 9 adds progress reporting

### Stage 4 notes

- **Custody store:** one streaming pass both writes and hashes, so the
  stored copy is exactly the hashed bytes. The copy is read back from disk
  before it is accepted. Objects are content-addressed and read-only.
  Records are canonical, and loading a record re-verifies its object.
  Source names are kept as data, losslessly.
- **Package v1** (`vault/package.py`): a prelude, a canonical manifest that
  binds each object's SHA-256 and exact length, the format version,
  transfer id, creation time and sender instance and key, then a signature
  block, the unmodified payload, and a trailer. The writer re-checks every
  object against its intake identity while streaming. It writes the trailer
  last, so a failed or interrupted write never verifies.
- **Verification** fails closed at the first problem. The signature is
  checked before any payload byte is read. A missing verifier is an error;
  there is no unauthenticated mode.
- **Read-back** drops cached pages, re-verifies the medium against the
  intake identities, and compares the result with what was written.
- **Release** stages inside the destination and publishes only after the
  whole package has verified, using a no-overwrite link (with a rename
  fallback on FAT). Unsafe or duplicate names are refused, or with
  `generate` replaced by Guardian names, while the receipt keeps the
  original. Bytes are never changed.
- **Deferred, with reasons** (no change to the stage order otherwise):
  - **Encryption, key management, rotation and locking** need key material
    that D2 says may only come from the YubiKeys, so they move to Stage 5.
    Integrity never depends on them (D1).
  - **Broker operations for intake, build and release** move to Stage 5.
    They need `owner_key`, and the client must pass open file descriptors
    (SCM_RIGHTS) so the root broker never opens client-supplied paths. Package
    parsing on the receiving side will run in a worker that receives the
    fd.
  - **Drive layout** (D4 steps 3–5): the package is medium-independent and
    works at offset 0 of a raw device or as a file. Raw layout, with no
    filesystem for the OS to automount or parse, suits Linux and Windows.
    Termux cannot open raw devices, so the layout choice per platform and
    the whole-volume check for a filesystem layout belong to Stage 7.

### Stage 5 notes

- **Owner keys** are FIDO2 security-key SSH keys (`sk-ssh-ed25519`)
  created on each YubiKey. Signing goes through `ssh-keygen -Y sign`: touch
  only, no PIN. Verification goes through `ssh-keygen -Y verify` with one
  allowed-signers entry per call, restricted to one namespace and without
  `no-touch-required`, so an untouched signature does not verify. It runs
  in a sandboxed worker, and signature input reaches it through pipes.
  Requirement: `openssh-client` (Debian/MX, Termux and Windows all ship it).
- **Trust log** (`identity/trust.py`): a hash chain of signed events
  (genesis, enroll, revoke) with a pinned anchor.
  - At most two keys are active. Either key alone authorizes, and either
    can revoke or replace the other (D3).
  - A revoked key never returns, and its signatures, even old ones, are
    rejected.
  - The last key cannot be revoked; losing every key means re-rooting from
    known-good media.
  - Forks and anchor mismatches fail closed.
  - Serial numbers are labels only. Production accepts only hardware key
    types.
- **Owner assertions** (`identity/owner.py`): challenge, one touch, then a
  one-shot grant bound to the connection, the uid, the operation and the
  digest of its exact parameters. A signed manifest or trust event is
  itself the owner proof for writing it. There is no session-wide unlock.
  That is how "locking" is met: nothing is ever left unlocked.
- **Key rotation** means revoking and enrolling through the trust log, so
  there are no epochs of secret material to rotate.
- **Broker operations**: `auth.*`, `trust.*`, `vault.intake`,
  `transfer.prepare/write/verify/release`. Files and directories arrive as
  passed descriptors (SCM_RIGHTS), so the broker never opens client paths.
  Released files belong to the requesting user. Payloads never cross JSON
  frames.
- **Not yet validated on hardware:** CI has no YubiKey. The identical code
  path is tested with real `ssh-keygen` and ordinary ed25519 keys under an
  explicit test-only key-type policy. These must be checked on MX with the
  owner's two YubiKeys:
  - creating `ed25519-sk` keys
  - that signing needs a touch
  - that an untouched signature is refused
  - backing up the key handles
- **Deferred again: optional encryption.** No PIN-free, YubiKey-backed
  encryption tool is packaged in Debian/MX: `age-plugin-yubikey` is not
  in Debian, and the standard library has no AEAD cipher. Adding one
  means a new dependency (`age` with a FIDO2 plugin, or
  python3-cryptography with `fido2-tools` hmac-secret). That is an owner
  decision (D7, pending). Integrity does not depend on it (D1).
- **Not built yet: the signed audit ledger** that the threat model relies on
  to spot unexpected signatures. Today the broker logs every authorization
  decision and outcome to its private log; the hash-chained, signed ledger
  is planned with Stage 8 (artifact verification and reports).
- The receiving broker parses the bounded, strictly canonical manifest
  itself (stdlib `json`). Only signature checking is sandboxed. This is an
  accepted residual risk, since payload bytes are never parsed.

### Next: Stage 6

Guardian Forge: spinoff packages built with the Stage 4 package format and
signed with owner keys. Each spinoff carries the pinned trust anchor and a
copy of the trust log, and receives a capability profile and instance id.
A spinoff never holds signing authority. D5 (offline revocation and
certificate expiry) is needed before spinoff certificates are final.

## Owner decisions (2026-10-05)

These decisions override the build guide where the two differ.

**D1. Threat model: integrity first, on a host that may be compromised.**
Assume an attacker can watch the screen and log every keystroke. The goal is
not secrecy. The goal is to guarantee that data has not been altered or
tampered with. As a result:

- Guardian never asks for a password, passphrase or PIN, and never shows a
  secret on screen. What an observer sees or types gives them nothing that
  lets them forge anything.
- Everything Guardian produces carries a signature made on a YubiKey:
  custody manifests, transfer packages, deployment packages, epochs,
  revocations and audit entries. Incoming data does not need to be signed.
  Guardian establishes its own integrity identity at intake (D6). Signatures use the Stage 1 canonical encoding and domain
  tags. Checking a signature needs only the enrolled public keys, never a
  YubiKey or a secret. That means Termux and Windows spinoffs can verify
  everything offline.
- A touch confirms presence, not content. Signing therefore happens only
  from a known-good boot, and results are verified on a second instance (see
  SECURITY_MODEL.md, Threat model).
- Encryption is still available, but it is an extra on top of integrity, not
  the guarantee. Any encrypted object is also signed.
- Stage 4 "Encryption Vault" becomes an *integrity vault*. Its contents are
  stored signed and checked on every read; confidentiality is optional.

**D2. Unlocking: touch only, no PIN.**
Both keys are used for presence-gated signing (FIDO2 `ed25519-sk`, or PIV
with PIN policy "never" and touch policy "always"). Each signature needs a
physical touch. The trade-off is accepted: whoever holds a key can sign
with it. A keylogger would capture a PIN on a compromised host anyway, so a
PIN adds little here.

**D3. Two keys: either key alone works; either can revoke and replace the other.**
*(Settled 2026-10-05. This supersedes the earlier asymmetric recommendation.)*
- Either enrolled key independently authorizes owner operations. One serves
  as the backup for the other. Both are never required at once.
- A lost or retired key is revoked by a revocation signed with the remaining
  key. A replacement key is enrolled by an enrollment record signed with the
  remaining key. There is no password, PIN or recovery-phrase fallback.
- Serial numbers are identifiers only. Authentication is always fresh
  cryptographic proof from an enrolled key, with touch required for
  sensitive operations (D2).
- Accepted risk: someone who steals one key can revoke the other first.
  Mitigation inside the existing design: revocations and enrollments are
  accepted only when signed from the known-good boot (D1), are recorded in
  the audit ledger, and are shown on the second-instance verification. If
  both keys are lost or contested, trust is re-rooted from known-good media.

**D4. Guardian drives are dedicated and may be destroyed and rebuilt freely.**
Only drives used for Guardian are ever plugged in. Whatever it takes to make
sure a drive does not carry malware or hidden code forward, Guardian does
it. The required preparation sequence is:

1. **Interface allowlist before the kernel binds any driver.** A drive that
   presents anything besides one mass-storage interface (keyboard/HID,
   network, serial, a second storage function) is refused. This is how
   BadUSB attacks show up. New USB devices stay unauthorized until checked,
   via `authorized_default=0` and per-interface authorization or usbguard.
   The check repeats on every insertion, because firmware can change what it
   presents.
2. **Full-surface destruction and capacity proof.** Write the entire logical
   address space with a keyed pseudo-random pattern, then read it all back
   and compare. The key is fresh for each run, so firmware cannot predict
   the pattern or fake the result. This removes every partition, hidden
   partition, boot sector and slack area, and it exposes fake capacity.
3. **Rebuild from nothing.** Write a new partition table and a fresh
   filesystem with generated, fixed parameters. Nothing is carried over.
4. **Signed contents and whole-volume verification.** Every file Guardian
   writes is signed. After writing, the whole filesystem is inventoried
   (as `mx_usb_airlock` already does for its clean drive). Anything not in
   the signed manifest fails the drive.
5. **Verify on every later insertion**, on any Guardian instance, using only
   the public keys.

Drive identity (D4): every step re-checks the device's identity
fingerprint. A drive whose observable identity or expected state changes
between steps or insertions is rejected. Encryption from first provisioning
remains an option (D1); integrity never depends on it.

D4 is about the *drive*. It never touches payload bytes, which may
themselves be malicious and are preserved exactly (D6).

Limit that no software can remove: a stick's controller firmware and its
spare (over-provisioned) flash are out of reach of the host. Malicious
firmware could misreport its interfaces later or return different data to
different hosts. Steps 1, 2 and 5 detect such behaviour whenever it shows up
on a Guardian instance, but cannot prove the firmware is clean. To close the
gap, use drives with signed, non-updatable firmware or a hardware
write-protect switch for read-only roles such as the Rescue USB.

**D5 (pending).** Offline revocation and certificate expiry for spinoffs
(design review item 5) is waiting on the owner.

**D7 (pending). Optional encryption dependency.** Confidentiality needs an
AEAD cipher and a PIN-free YubiKey-backed key. Neither is in the standard
library or packaged in Debian/MX in a form that meets D2. Options: `age`
with a FIDO2/PIV plugin, or python3-cryptography plus `fido2-tools`
(hmac-secret). Waiting on the owner.

**D8 (recorded 2026-10-06). Space-exhaustion watchdog integration.**
The owner is having an external watchdog designed elsewhere. It detects
attacks that fill writable space to slow or stop work. Requirements for
integrating it:

- **Contract:** watchdog → broker only, as alerts over the existing
  socket. The watchdog runs as its own account with a policy entry
  granting one new capability (`watchdog.report`, no owner factor).
  Alerts are strictly validated canonical JSON.
- **Alerts can only restrict.** An alert can pause intake, transfer
  writes, releases and device preparation. It can never trigger deletion,
  grant capabilities, satisfy `owner_key`, or bypass verification.
  Resuming is an owner operation (touch).
- **Guardian-side gap to close regardless:** check free space (statvfs)
  with a kept-back reserve before intake into the custody store, package
  writes and release staging. Today those fail mid-way on a full disk. Data
  stays safe (everything is staged and verified), but they should refuse
  up front with a clear error.
- **Review first.** The watchdog's code is externally produced and must be
  reviewed against this security model before integration. Waiting on its
  interface: what it monitors, its alert format, and any autonomous actions.

**D6. Custody integrity: Guardian attests custody, not provenance.**
*(Settled 2026-10-05.)*
Guardian is responsible for data only from the moment it accepts it. It
makes no claim that incoming data was correct, authentic or clean. What it
guarantees is that the receiving Guardian releases exactly the bytes the
sending Guardian accepted, and fails closed otherwise.

1. **Payload bytes are opaque and never modified.** There is no
   normalization, repair, re-encoding, sanitization or newline conversion of
   payload bytes. A future transformation must produce a new object with its
   own integrity identity and a recorded link to its source.
2. **Identity at intake.** Guardian streams SHA-256 over the exact bytes and
   records the exact length. A canonical custody manifest (Stage 1 encoding,
   domain tag `guardian/custody/v1`) binds the payload digest and length, the
   format version, immutable transfer metadata (transfer id, intake time,
   source name as data), and the sending instance and key identity. The
   manifest is signed with an owner key (Stage 5).
3. **Untrusted metadata is never evidence.** Filenames, timestamps, sizes
   reported by the OS and directory listings never replace digest and length
   checks. Original filenames are recorded in the manifest as data. Release
   writes under a validated name. If the original name is unsafe for the
   target filesystem, the release refuses it or uses a Guardian-generated
   name, and the manifest keeps the original. Payload bytes are unaffected
   either way.
4. **USB read-back.** After writing a transfer, Guardian reads back what is
   actually stored (bypassing the page cache, as the Stage 3 surface test
   does) and checks it against the intake identity. A successful write call
   is not evidence.
5. **Receiving side.** Verify the manifest signature against the enrolled
   keys and the revocation state. Then verify the package. If it is
   encrypted, decrypt it. Then verify the payload digest and length again
   before release. Any mismatch blocks the release.
6. **Payloads never travel through JSON IPC.** They are hashed and copied as
   streams through file descriptors. Only digests, lengths and manifests
   cross broker/worker frames, which are limited to 1 MiB.

Stage mapping: Stage 4 implements the custody object store and the
transfer package format (2, 3, 4, 6); Stage 5 adds the signatures and key
lifecycle; Stage 6 reuses the package format for deployments; Stage 8 adds
artifact and erase verification reports. The verified-release design of
`mx_usb_airlock` (whole-destination verification) is the reference.


## Design review of the build guide

The guide's goals stand. The points below adjust how some of them have to
be met for the security claims to hold.

1. **Hardware identifiers are not authentication.** A YubiKey serial number
   can be read and copied freely. Enrollment must record a public credential
   (FIDO2 credential ID and public key, or a PIV/OpenPGP public key), and
   every unlock must be a fresh cryptographic challenge against it. The
   serial is metadata only.

2. **Two keys: either-of-two or both-required.** *(Resolved by D3.)* The guide implies that
   either enrolled key unlocks Guardian, with key B as the spare for key A.
   Envelope encryption supports that directly: the vault master key is
   wrapped separately for each key (for example with FIDO2 `hmac-secret` or
   PIV key agreement). If both keys must ever be required (2-of-2), losing
   either one locks the owner out permanently. The owner should make this
   choice explicitly before Stage 5. Either-of-two plus offline revocation of
   a lost key is the recommended default.

3. **"Master secrets never outside hardware" is true at rest, not in use.**
   *(Mostly moot under D1: integrity rests on signing keys that never leave
   the YubiKeys. Only optional encryption keys are ever held in memory.)*
   Envelope encryption needs the unwrapped master key in the broker's memory
   while the vault is unlocked. The honest guarantee is that at rest the
   master key exists only wrapped to the enrolled YubiKeys, and that it is
   held in memory only by the privileged, non-dumpable broker, never by
   workers or UI processes.

4. **Rotation has two different costs.** Rotating a wrapping key or epoch
   (re-wrapping the master or file keys) is cheap. Rotating the data keys
   means re-encrypting the data. Old epoch keys have to be kept until all
   data under them has been re-encrypted. Revocation of a spinoff must
   include such a re-key, or the spinoff can still read what it already had.

5. **Offline spinoffs cannot be revoked instantly.** *(Pending, D5.)* A spinoff that never
   syncs never learns that it was revoked. The fix is short-lived deployment
   certificates with an expiry and a minimum required epoch. Revocation then
   takes effect no later than the expiry. Spinoff certificates must never
   carry signing authority (rule: spinoffs never become authorities).

6. **Signing keys belong on the YubiKeys.** Forge signatures should be
   produced on the token (PIV/OpenPGP signing, or FIDO2 through
   `ssh-keygen -Y sign`) and verified against the enrolled public keys. The
   canonical JSON format (an RFC 8785 subset) and the domain-separated
   digests in Stage 1 exist so that Linux, Termux and Windows verifiers hash
   exactly the same bytes.

7. **Controller and firmware data on USB sticks is limited.** Standard
   interfaces expose USB descriptors (VID/PID, strings), the SCSI INQUIRY and
   capacity, and sometimes SMART behind SATA/NVMe bridges. The flash
   controller model and its firmware on typical sticks and SD cards are
   reachable only through vendor-specific tools, and flashing them is risky.
   Stage 8 should report what is exposed and flag inconsistencies, and must
   not claim firmware verification that cannot be done.

8. **Fake-capacity detection is destructive.** *(Accepted by D4.)* Proving the real capacity
   means writing and reading back the full advertised size (as f3 does). It
   is a `device.modify` operation and needs explicit confirmation.

9. **Erasing flash cannot be fully verified.** *(Handled by D4.)* Wear levelling and spare
   blocks mean an overwrite only verifies the logical address space. Use
   device sanitize commands where they exist. The reliable approach is to
   encrypt from the first write and destroy the key (crypto-erase).

10. **Platform limits.** Termux cannot access raw block devices without
    root. USB OTG access goes through the Android USB host API
    (`termux-usb`), and YubiKey access there is limited too. Windows needs
    its own service and broker built on Windows security primitives, as the
    guide says. Only the formats (canonical JSON, signatures, epochs) are
    shared across platforms.
