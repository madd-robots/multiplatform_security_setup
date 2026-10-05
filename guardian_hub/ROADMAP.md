# Roadmap

This file follows the stage order of the Guardian build guide (v1.0) and
records where the implementation deviates from it and why.

## Stage status

| Stage | Scope | Status |
|---|---|---|
| 1 Foundation | common library, errors, canonical serialization, safe filenames, logging, tests | **Done** (`usbguardian/common`) |
| 2 Security runtime | privilege separation, broker, worker isolation, IPC, authorization | **Done**, with the hardening listed below still open (`usbguardian/runtime`) |
| 3 Device engine | USB detection, storage identity, vendor and controller data, capacity verification | Not started |
| 4 Encryption vault | file encryption, key management, rotation, locking | Not started |
| 5 YubiKey integration | enrollment, authentication, owner verification | Not started |
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

### Next: Stage 3

Device enumeration (`lsblk` JSON, sysfs, mountinfo) runs as worker handlers
with `allow_subprocess` only where a tool must run. Parsing follows the
approach that is already proven in `mx_usb_airlock`. Read-only analysis uses
the `device.inspect` capability. Anything that writes to a device uses
`device.modify`, which needs `owner_key` and therefore stays unavailable until
Stage 5. Stage 3 also has to meet the drive requirements in decision D4
below.

## Owner decisions (2026-10-05)

These decisions override the build guide where the two differ.

**D1. Threat model: integrity first, on a host that may be compromised.**
Assume an attacker can watch the screen and log every keystroke. The goal is
not secrecy. The goal is to guarantee that data has not been altered or
tampered with. As a result:

- Guardian never asks for a password, passphrase or PIN, and never shows a
  secret on screen. What an observer sees or types gives them nothing that
  lets them forge anything.
- Everything Guardian produces or accepts carries a signature made on a
  YubiKey: files, manifests, deployment packages, epochs, revocations and
  audit entries. Signatures use the Stage 1 canonical encoding and domain
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

**D3. Two keys: either key alone works, and a lost key can be revoked.**
Key A is the daily key. Key B is the backup and is kept offline. Either key
can sign anything on its own. Recommended default for revocation: **only
the backup (B) can revoke or replace the daily key (A); A cannot revoke B.**
With symmetric revocation, a thief holding A could revoke B first and lock
the owner out. If B itself is lost, the owner re-roots trust by reinstalling
the trust anchor from known-good media. Confirm or change this before
Stage 5.

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

Limit that no software can remove: a stick's controller firmware and its
spare (over-provisioned) flash are out of reach of the host. Malicious
firmware could misreport its interfaces later or return different data to
different hosts. Steps 1, 2 and 5 detect such behaviour whenever it shows up
on a Guardian instance, but cannot prove the firmware is clean. To close the
gap, use drives with signed, non-updatable firmware or a hardware
write-protect switch for read-only roles such as the Rescue USB.

**D5 (pending).** Offline revocation and certificate expiry for spinoffs
(design review item 5) is waiting on the owner.

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
