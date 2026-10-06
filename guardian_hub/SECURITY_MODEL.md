# Security model (Stages 1 to 7, audit ledger, offline leases)

## Threat model (owner decision D1, see ROADMAP.md)

Guardian runs on hosts that may be compromised. The attacker may watch the
screen and log every keystroke. The goal is **integrity**: proof that data
and deployments were not altered. Secrecy comes second.

- No passwords, passphrases or PINs are ever asked for or shown. The owner's
  authority is a physical touch on an enrolled YubiKey, and the signing keys
  never leave the keys.
- Checking a signature needs only public keys, so a compromised host cannot
  gain anything by watching verification.
- **The limit no design removes: what you touch to sign is not what you
  see.** A YubiKey has no screen. Malware on the host can swap the digest
  sent to the key, and the touch then signs the attacker's content. Each
  touch yields at most one signature, but every signature needs a touch.
  Rules that follow from this:
  1. Sign only from a known-good environment: the Guardian Rescue USB,
     booted read-only, never an everyday installed OS.
  2. Verify on a second, independent Guardian instance (for example the
     Termux spinoff) before trusting anything that was signed.
  3. Every signature is to be recorded in the signed, hash-chained audit
     ledger, so an unexpected signature shows up afterwards. The ledger is
     planned (Stage 8); until then the broker's private log records every
     authorization decision.
- On a compromised host, Guardian's own display of a result can be forged.
  A verification only counts when it runs on an instance you trust.

## Trust boundaries

```
 UI / CLI client            broker (root)                     worker (dedicated uid)
 any local uid  --socket--> identity: SO_PEERCRED   --pipes--> parses untrusted data
                            policy: uid -> capabilities          no privileges, limits,
                            validates everything                 NO_NEW_PRIVS, not dumpable
```

- **Client to broker.** The kernel supplies the client's uid, so a client
  cannot claim a different identity. Each uid maps to an explicit
  capability set. Root gets nothing implicitly. Unknown uids are refused
  before any request is read.
- **Broker to worker.** Workers are untrusted once they have read their
  input. Their output must be exactly one canonical frame within size and
  time limits from a process that exits 0. Anything else is a failure.
  Workers are never reused.
- **Configuration.** The policy file, the code tree and the interpreter must
  be owned by root and not writable by others when the broker runs as root.
  Workers never prepend their own directory to `sys.path`, so code next to
  the package cannot shadow the standard library.

## What is enforced today

- Default deny. An operation runs only if the principal holds its
  capability. Authorization happens before parameter validation, so an
  unauthorized client learns nothing from validation errors.
- Capabilities that touch keys, vaults, deployments or device contents need
  the `owner_key` factor. Nothing can grant that factor until Stage 5
  (YubiKey), so these operations are unreachable for now.
- Worker sandbox, set up and verified before any input is read:
  - setgroups/setresgid/setresuid to the worker account, with a check that
    root cannot be regained
  - RLIMIT_CORE 0, CPU and memory limits, an open-file limit, RLIMIT_FSIZE 0
    (no file writes), RLIMIT_NPROC 0 (no fork)
  - NO_NEW_PRIVS and non-dumpable, with umask 077, cwd `/`, a two-variable
    environment and no inherited descriptors
  - its own session, so the whole process group is killed on timeout
- The broker makes itself non-dumpable, which blocks same-uid ptrace and
  core dumps.
- Every frame on the socket and on worker pipes is canonical JSON, at most
  1 MiB, and read against a deadline. Duplicate keys, floats, BOMs, lone
  surrogates and excessive nesting are rejected.
- Errors cross boundaries only as a code plus a sanitized message.
  Tracebacks and internal exception text are never sent.
- Logs are JSON lines in ASCII. Secret-named fields are redacted, binary data
  is never logged, untrusted text is escaped, and files are 0600, opened with
  O_NOFOLLOW and rotated.

## Device engine (Stage 3)

- Device-reported data (USB strings and descriptors, SCSI INQUIRY, MMC CID,
  mount points) is parsed only in workers, with bounded reads, symlinks
  confined to sysfs, and values kept exactly as reported. Non-UTF-8 values
  are encoded as hex rather than altered.
- A device fingerprint is computed from values the device reports. It
  detects a change in presented identity. It does not prove physical
  identity, because a malicious device can copy another's descriptors.
- Before the destructive surface test, the broker validates the worker's
  report and checks it against values it reads from sysfs itself (device
  number, bus topology, holders, size). It opens the node with O_EXCL and
  confirms its major:minor, so a lying worker cannot redirect the
  overwrite to another disk.
- The surface test proves the logical address space was overwritten and
  read back correctly. It cannot reach controller firmware or spare flash
  (ROADMAP D4).

## Integrity vault (Stage 4, ROADMAP D6)

- Guardian attests **custody, not provenance**. It makes no claim that
  incoming data was correct or safe. It guarantees that the receiving
  Guardian releases exactly the bytes the sending Guardian accepted.
- Payload bytes are opaque. They are never normalized, converted or
  sanitized. Malicious content is carried unchanged, because analysing it is
  a separate job.
- Every release is authenticated: the manifest signature binds each
  object's SHA-256 and exact length. An attacker who rewrites the medium
  can recompute every hash, but cannot produce the signature without an
  enrolled key. The signature is checked before any payload byte is read,
  so an unauthenticated package cannot make Guardian write anything.
- Until Stage 5 there is no production verifier, so **nothing can be
  released**. That is intended (fail closed).
- Release never overwrites. Nothing appears under a final name before the
  whole package has verified, and a failure leaves the destination
  unchanged. File names are the only thing that can differ from the
  source, and only under the `generate` policy, with the original kept in
  the receipt.
- Limit: the custody store and the receiving staging area trust the local
  filesystem of the Guardian host while the transfer runs. Integrity across
  the USB transport is cryptographic; integrity on a compromised host
  during processing is bounded by the D1 rules (known-good boot, second
  instance).

## Owner keys and assertions (Stage 5)

- Authority comes from fresh signatures by enrolled YubiKey security keys.
  Each one needs a touch; no PIN is used. A key's serial number is never
  used to authenticate.
- Each touch authorizes one thing: a specific request (challenge-bound,
  single use, tied to the connection, uid and exact parameters), a specific
  manifest, or a specific trust event. Signatures are domain-separated by
  namespace, so one made for one purpose is useless for another.
- Signature verification sees only one enrolled key and one namespace per
  call, and runs `ssh-keygen` inside the sandboxed worker.
- The trust log is signed and hash-chained from a pinned anchor. A revoked
  key, or any key not in the active set, is rejected everywhere.
- Accepted risk (D3): someone holding one stolen key can revoke the other
  first. Detection relies on the second-instance check and, once built,
  the audit ledger. Recovery is re-rooting from known-good media.
- Not yet validated with real YubiKeys (see ROADMAP Stage 5 notes).

## Spinoff deployments (Stage 6)

- A deployment authorizes nothing by itself. It carries public keys only,
  and no profile can contain Forge capabilities, so a spinoff cannot sign,
  enroll keys or build further spinoffs.
- A target trusts a deployment only against a pinned anchor and a trust
  log brought on known-good media, never against the package's own
  snapshot alone. Diverging logs are refused as a fork.
- Deployment and transfer signatures use separate namespaces and cannot
  be interchanged.
- Authority to act comes from a separate, expiring lease (below), not from
  the deployment.

## Installation (Stage 7, Debian/MX)

- The installer trusts only the pinned anchor and trust log the owner
  brings on known-good media. Signatures are checked in the sandboxed
  worker as the dedicated worker account.
- Installed code is root-owned and not writable by others. The broker
  re-verifies this itself at every start before it runs a worker.
- An install either completes after full verification or changes nothing.
  An existing machine's trust state can only be extended, never forked or
  re-anchored, by an install.
- USB interface blocking at the kernel level is supplied as a reviewed
  suggestion, not applied, because applying it blindly can lock out input
  devices.

## Audit ledger (handoff H1)

- Every authorization decision and every outcome is appended to a hash
  chain before the operation runs. If the ledger cannot be written, an
  allowed operation is refused. A broken chain stops the broker at start.
- Edits, deletions, reordering and truncation inside the chain are
  detected. Root can rewrite the chain from some point onward; an
  owner-signed checkpoint (one touch) fixes the head, so a rewrite before
  it is detectable, best checked on another instance from a copy.
  Entries removed after the last checkpoint, at the end, are not
  detectable without an external copy.
- Secrets never enter it: fields are redacted like log fields; only
  Guardian-generated signatures and digests are stored byte for byte.

## Offline leases (ROADMAP D5)

- A spinoff holds authority only under a lease signed by an owner key
  through Guardian Main (one touch), bound to its instance id, a machine
  binding, a generation and a key the spinoff generated itself. Without
  an ACTIVE (or EXPIRING) lease it refuses intake, writing transfers and
  destructive device work. Verification and release of existing data
  never need a lease: authorization is separate from recovery.
- A spinoff cannot extend, renew or un-revoke itself, lower its
  generation or sequence, or issue anything: it has no issuing operation,
  and its records need an owner signature it cannot make.
- Sequences only increase. Stale, replayed, misbound or rolled-back
  records are refused. Revocation, supersession and an observed expiry are
  sticky; setting the clock back revives none of them.
- A clock behind the highest time already observed (beyond 5 minutes)
  makes the state UNKNOWN, which fails closed. A newer owner-signed lease
  is the way out of a clock that once ran far ahead.
- **Limits.** An offline spinoff loses authority only when a revocation is
  imported, its lease expires, or it learns it is superseded; instant
  remote revocation is impossible. The machine binding is a digest of DMI
  and machine-id values, which root can fake and a disk clone carries; it
  is not attestation. Without protected non-rollback storage (for example
  a TPM), root can delete the lease state. Replacing it with an older copy
  is detected while the audit ledger is intact; deleting both is not. A
  wrong system clock that runs *ahead* only shortens a lease.

## USB Airlock (ROADMAP D10, handoff H4)

- RED media is hostile. Its identity (USB descriptors, interfaces) and its
  layout (partition table, ESP, boot flags, boot code, overlaps, GPT
  checksums) are inspected in sandboxed workers before anything mounts
  it. Storage that also presents HID, network or other unexpected
  interfaces is BLOCKED; unusual layouts need review; nothing is repaired.
- Acquisition needs an owner touch, re-checks the device identity before
  mounting and after unmounting, and mounts one volume `ro,noexec,nodev,
  nosuid` (ext: `noload`, so no journal replay). The walk never follows
  symlinks, skips special files and system folders, and bounds entries,
  depth, file size and total size. Quarantine copies get generated names,
  no execute bits, and are checked against the space reserve.
- Each file is inspected without execution: type from content (extension
  mismatches flagged), static review of shell and PowerShell, text tricks
  (bidi, zero-width, encoded blobs), PDF and macro markers, archives
  listed with member, size, ratio, traversal and link limits (never
  extracted), and ClamAV as one signal. A missing or failing scanner
  blocks (fail closed).
- Export needs an owner touch bound to the exact items, their hashes and
  the GREEN device identity. RED must be detached; GREEN must not be RED
  and the destination directory must be on GREEN. Each file is re-hashed,
  written to a fresh folder (no overwrite), read back with the page cache
  dropped, and only then renamed into place; any mismatch stops the export
  (TRANSFER_INTEGRITY_FAILURE). Only files are written: no partition
  table, boot sector, EFI partition or volume image.
- **Limits.** Mounting hostile media exposes the kernel's filesystem
  driver; read-only options reduce, not remove, that risk. An inspection
  worker exploited by a hostile file could misreport its results; the
  sandbox limits what else it can do, and the owner still has to approve.
  Static review finds constructs, not intent, and a clean scan is not
  proof. Real mounts, ClamAV reopening quarantine files through
  `/dev/fd`, and BadUSB detection on real hardware are hardware-gate
  items (validated only in tests with fakes so far).

## Watchdog boundary (ROADMAP D8, handoff H3)

- The external watchdog's interface does not exist yet, and Guardian does
  not depend on it. The adapter is disabled by default and reports are
  refused. A real adapter will be written only after its interface has
  been reviewed.
- The only thing an adapter can hand to Guardian is a signal: a kind and
  a severity from fixed lists, plus escaped display text. Guardian's own
  policy decides: a critical space signal pauses intake, transfer and
  deployment writes, releases and destructive device work. Nothing else
  can follow from a signal: no resume, no capability, no owner factor, no
  lease or trust change, no file or device choice, no command.
- The watchdog's account needs only `watchdog.report`. Resuming is an
  owner touch (`watchdog.resume`). Pauses persist across restarts, hold in
  memory even if the disk is too full to save them, and an unreadable
  pause file pauses everything (fail closed).
- A compromised reporter can pause work (denial of service); that is the
  accepted cost of a restrict-only channel.

## Space exhaustion (ROADMAP D8)

- Every Guardian write path checks free space and free inodes against a
  reserve before it starts, and re-checks while it runs. Filling the disk
  can make Guardian refuse or stop work, but it cannot make Guardian leave
  partial or unverifiable results behind, or spend a YubiKey touch on a
  write that cannot fit.
- The space check is advisory against a determined local attacker: space
  can still be taken between two checks. The guarantee that holds is the
  fail-closed one above, not uninterrupted service. Detecting and
  responding to fill attacks is the external watchdog's job (D8).

## Known limitations (not hidden, not yet fixed)

- **No syscall filter, Landlock or network isolation for workers yet** (see
  ROADMAP). A worker running as the dedicated account can still open
  sockets and read world-readable files.
- **Development mode** (broker not root): workers share the user's uid.
  RLIMIT_FSIZE stops them writing data, but they can still unlink, rename
  or chmod that user's files, and they can signal other processes of that
  uid. Use development mode only for development.
- **The worker account must be dedicated.** Processes with the same uid can
  signal each other. Do not reuse `nobody` in production, because other
  services run as it. The test suite uses 65534 only because it is always
  present.
- **Authorization by uid alone** means any process running as an authorized
  uid has that uid's capabilities. The `owner_key` factor (Stage 5) is meant
  to require physical presence for anything sensitive.
- The broker has no rate limiting beyond the connection and concurrent-worker
  caps.
