# Guardian USB Encryption Hub

A personal USB security and recovery platform. YubiKeys are the owner's root
of trust, and Guardian Main builds signed spinoffs for Debian/MX, Termux and
Windows. The full plan, stage status and the design changes made along the way
are in [ROADMAP.md](ROADMAP.md). Read [SECURITY_MODEL.md](SECURITY_MODEL.md)
for what the code guarantees today and what it does not.

**Status: Stages 1–6 of 9 are implemented.** YubiKey support is tested with software keys; hardware validation on MX is pending. The owner decisions in ROADMAP.md (integrity-first threat model, touch-only YubiKeys, dedicated drives) govern the remaining stages. There is no device analysis,
encryption or YubiKey support yet. Each of those is a later stage, and the
operations that need them are refused by design until they exist.

## Layout

```
guardian_hub/
  guardian.py                 CLI: run the broker, call operations
  usbguardian/
    common/                   Stage 1 foundation
      errors.py               error hierarchy with stable codes
      canonical.py            canonical JSON (RFC 8785 subset), domain-separated digests, strict base64
      names.py                safe filenames and paths (Linux/Windows/Android), name sanitizer
      fsutil.py               O_NOFOLLOW reads, atomic private writes, trusted-file checks
      log.py                  structured JSON-line logging with redaction and 0600 rotation
      text.py                 safe rendering of untrusted text
      space.py                free-space and inode reserve checks (ROADMAP D8)
      tools.py                external tools only from root-owned system directories
    devices/                  Stage 3 device engine (Linux)
      scanner.py              sysfs/mountinfo collection (runs in the worker), kernel-side facts
      identity.py             device identity document, fingerprint, change detection
      assess.py               findings: BadUSB interface rules, internal/system/mounted disks
      surface.py              DESTRUCTIVE keyed full-surface write + O_DIRECT read-back
      handlers.py             worker handlers devices.scan / devices.inspect
      operations.py           broker ops device.list / device.inspect / device.surface_test
    vault/                    Stage 4 integrity vault (custody, ROADMAP D6)
      custody.py              private content-addressed custody store, intake with read-back
      package.py              transfer package v1: write, read-back, verify (fail closed)
      release.py              verify-then-release via staging, no overwrite, name policy
      auth.py                 signer/verifier interface
      operations.py           vault.intake, transfer.prepare/write/verify/release (fd passing)
    identity/                 Stage 5 YubiKey owner keys (ROADMAP D2, D3)
      sshkeys.py              strict OpenSSH public-key parsing, key ids, hardware-only policy
      sshsig.py               ssh-keygen -Y sign (touch) / verify (pipes, one key, one namespace)
      handlers.py             sandboxed signature verification worker
      trust.py                signed hash-chained trust log: genesis, enroll, revoke
      enrollment.py           client-side builders for trust events
      owner.py                challenge -> touch -> one-shot grant for one exact request
      operations.py           trust.status/log/init/append
    forge/                    Stage 6 Guardian Forge (spinoff deployments)
      profiles.py             platforms (availability) and capability profiles, never Forge rights
      descriptor.py           deployment descriptor schema, code inventory collection
      registry.py             Guardian Main's deployment registry (active / retired)
      service.py              forge.prepare / forge.write / forge.list / forge.retire
      install.py              target side: verify against a pinned anchor + trust log, extract code
    app.py                    assembles the broker from its services
    runtime/                  Stage 2 security runtime (Linux)
      ipc.py                  length-prefixed canonical frames, deadlines, size bounds
      schema.py               strict validators for every message and parameter
      authz.py                capabilities, policy by kernel uid, default deny, factor gating
      broker.py               validate -> authorize -> validate params -> dispatch
      server.py / client.py   Unix socket with SO_PEERCRED identity
      workers.py              one sandboxed process per job, bounded I/O, kill on timeout
      sandbox.py              privilege drop, rlimits, NO_NEW_PRIVS, non-dumpable
      worker.py               worker main loop
      handlers.py             worker handler registry
      testing_handlers.py     hostile handlers, loaded only by the test suite
  tests/
```

Requirements: Linux, Python 3.10 or newer (standard library only), and `openssh-client` for `ssh-keygen -Y`. MX Linux 23
(Debian 12, Python 3.11) is the reference target.

## Owner keys (once, from the Rescue USB)

Create one security-key SSH key on each YubiKey. The handle file is useless
without its YubiKey, but it cannot be recovered from the YubiKey either, so
back up both handles on the Rescue USB. Do not add `-O no-touch-required`
or `-O verify-required`: Guardian uses touch and no PIN.

```
ssh-keygen -t ed25519-sk -O application=ssh:guardian -N '' -f guardian-key-a   # YubiKey A inserted
ssh-keygen -t ed25519-sk -O application=ssh:guardian -N '' -f guardian-key-b   # YubiKey B inserted
python3 -I -B guardian.py key-info guardian-key-a.pub
python3 -I -B guardian.py trust-init --socket S \
    --owner guardian-key-a.pub guardian-key-a "Key A" --owner guardian-key-b.pub guardian-key-b "Key B"
```

Lost key B: `trust-revoke --subject <B key_id> --auth guardian-key-a.pub guardian-key-a`.
Then enroll its replacement through the remaining key with
`trust-enroll --new NEW.pub NEW "Key C" --auth guardian-key-a.pub guardian-key-a`.

## Running the broker

The real configuration is a root broker whose workers run as a dedicated
unprivileged account. The package tree, the interpreter and the policy file
must be owned by root and writable by nobody else; the broker checks this
and refuses to start otherwise.

```
sudo adduser --system --group --no-create-home usbguardian-worker
sudo install -d -m 0755 /run/usbguardian
sudo python3 -I -B guardian.py broker \
    --policy /etc/usbguardian/policy.json \
    --socket /run/usbguardian/broker.sock --socket-mode 600 --state-dir /var/lib/usbguardian \
    --worker-user usbguardian-worker \
    --log-file /var/log/usbguardian-broker.log
```

The policy file grants capabilities to kernel-verified uids. Nobody gets
anything implicitly, including root:

```json
{"principals":[{"capabilities":["runtime.diagnostics","runtime.status"],"name":"admin","uid":0}],"version":1}
```

Call an operation (`--socket-mode 660` plus a group is needed before
non-root users can connect):

```
sudo python3 -I -B guardian.py call runtime.status --socket /run/usbguardian/broker.sock
sudo python3 -I -B guardian.py call runtime.sandbox_report --socket /run/usbguardian/broker.sock
sudo python3 -I -B guardian.py call device.list --socket /run/usbguardian/broker.sock
sudo python3 -I -B guardian.py call device.inspect --params '{"kname":"sdb"}' --socket /run/usbguardian/broker.sock
```

`device.list` and `device.inspect` need the `device.inspect` capability.
`device.surface_test` overwrites the whole device. It needs `device.modify`
plus the YubiKey `owner_key` factor, so it is refused until Stage 5.

Running the broker as a normal user is **development mode**. Workers then
share your uid. They still get the resource limits and process flags, but
they are not separated from your files. The broker prints a warning when it
starts this way.

A SysVinit service and packaging are Stage 7 work.

## Tests

```
cd guardian_hub
python3 -I -B -m unittest discover -s tests -v
```

When the suite runs as root, workers drop to uid/gid 65534. This exercises
the production privilege-drop path, so the checkout must be root-owned and
not group- or world-writable. Run as a normal user, it tests development
mode. The suite covers:

- **Stage 1:** canonical encoding and strict parsing (duplicate keys, floats,
  BOM, lone surrogates, depth, non-canonical input), RFC 8785 key order and
  escapes, digest domain separation, strict base64, name rules (traversal,
  bidi, zero-width, homoglyphs, Windows reserved names, leading dash, NFC),
  fuzzing of the sanitizer, symlink and FIFO refusal, atomic writes, trusted
  file checks, log redaction, log injection and log rotation.
- **Stage 2:** frame bounds and timeouts, slow and silent peers, authorization
  (default deny, no implicit root, owner-key gating, authorization before
  parameter validation), policy file protection, and workers that spin,
  sleep, allocate, flood stdout or stderr, write files, fork, try to regain
  root, crash, or emit forged, extra or garbage frames. Also covered: the
  socket server's peer identity, connection limits, malformed frames and its
  refusal to replace non-socket paths.
- **Stage 3:** a fake sysfs tree (USB sticks, SD cards, NVMe, loop
  devices), BadUSB interface layouts (HID, network, vendor, extra storage,
  extra configurations), system, live, mounted and held disks, symlinks
  escaping sysfs, bounded and non-UTF-8 attributes, identity stability and
  change detection. Surface tests cover a clean pass, a fresh key per run,
  counterfeit wrap-around and dropped-write capacity, single bit flips, I/O
  errors and cancellation. The surface operation is tested for refusal on
  identity mismatch, blocking findings, a lying worker report, kernel
  topology disagreement and identity change mid-test, and for owner-key
  gating through the broker. Read-only scans also run in the real sandboxed
  worker.
- **Stage 4:** byte-exact round trips for CRLF, BOM, invalid UTF-8, NUL,
  empty, EICAR and PE-header payloads (never altered). A flipped byte in any
  package region is rejected, and so is an attacker who rewrites the
  payload, digests and trailer but lacks the owner key. Also covered:
  key-id/sender binding, non-canonical manifests, truncation, trailing data,
  swapped objects, oversized headers, the missing verifier, store and record
  tampering, read-back of a corrupted or different medium, raw-device
  offsets, release name policies, no-overwrite release and cleanup after a
  late failure. Signatures in these tests use a test-only HMAC verifier.
- **Stage 5** (real `ssh-keygen`, ordinary ed25519 keys under an explicit
  test-only policy): key parsing and fingerprints, namespace separation,
  armor checks, and a handle/key mismatch. Trust-log tests cover:
  - the full lifecycle, two-key limit, possession proofs and outsider keys
  - revoked keys returning, last-key protection, forks and anchor pinning
  - store tampering, and old signatures by revoked keys

  Owner-assertion tests cover one-shot grants bound to parameters,
  connection, op and uid, nonce reuse and expiry, revoked or outsider keys,
  and a missing capability. End-to-end socket tests cover fd passing,
  intake, signing, write with read-back, verify, release with the backup
  key, refusal without a touch, revocation applying to existing packages,
  replacement enrollment, fd validation and fd-count mismatch. Two
  mutations (grant not consumed, uid not bound) were confirmed to fail the
  suite.
- **Free space (D8):** reserve arithmetic, the inode check (skipped on FAT),
  and re-checks during writes. Intake, package write and release are
  refused up front, and stopped cleanly when the disk fills mid-way
  (simulated statvfs). No partial copies or staging are left behind,
  interrupted packages never verify, and a refused package write never
  asks for a signature.
- **Stage 6:** spinoffs never receive Forge capabilities, and unavailable
  platforms are refused. The build is tested end to end through the broker,
  then verified and extracted; the code comes out byte-identical with
  test-only handlers excluded. Also covered:
  - building with the backup key
  - namespace separation in both directions, and refusal of outsider keys
  - pinned anchor mismatch, later trust logs accepted, diverging logs
    refused as forks
  - revoked issuers, unique instance ids, retirement needing a touch
  - wrong platform, expired descriptors, and wrong package layout
- **Hygiene:** no `shell=True`, `eval`, `exec`, `pickle`, dynamic imports or
  unbounded reads; ASCII-only, licensed, stdlib-only sources.
