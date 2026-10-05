# Security model (Stages 1 to 3)

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
  3. Every signature is recorded in the signed, hash-chained audit ledger,
     so an unexpected signature shows up afterwards.
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
