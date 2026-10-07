# Guardian USB Encryption Hub

A personal USB security and recovery platform. YubiKeys are the owner's root
of trust, and Guardian Main builds signed spinoffs for Debian/MX, Termux and
Windows. The full plan, stage status and the design changes made along the way
are in [ROADMAP.md](ROADMAP.md). Read [SECURITY_MODEL.md](SECURITY_MODEL.md)
for what the code enforces today and what it does not.

**Status.** Stages 1 to 6 are implemented, Stage 7 for Debian/MX, and the
owner handoff items: audit ledger, offline leases (D5), watchdog boundary,
USB Airlock (D10), SysVinit preflight and installer v2 with an offline
bundle (D9, D11), and `age` capsule mechanics (D7). Termux, Windows, the
Stage 8 reports and the Stage 9 UI are not started. Everything is tested
here with software keys, fixtures and fakes; **nothing has yet run on the
MX machine with the two YubiKeys** (see "Hardware gates" in ROADMAP.md).
Hardware-backed encryption is not offered until the D7 gate passes.

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
      capsule.py              age capsules, owner-signed recipient sets (D7; behind the hardware gate)
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
    lease/                    D5 offline authorization leases
      records.py              lease request, lease and revocation documents
      machine.py              machine binding digest (DMI, machine-id); not attestation
      spinoff.py              spinoff lease state, its own key, the ACTIVE gate, clock high-water mark
      issuer.py               Guardian Main: issue, renew, reissue, revoke; generations in the registry
    assurance/                Stage 8 device assurance
      facts.py                exposed facts, firmware indicators, what cannot be verified, inconsistencies
      drives.py               registry of erase-verified drives; changed identity -> rejected
      reports.py              reports recorded in the audit ledger, owner-signable, verifiable offline
      service.py              assurance.* operations, trusted-artifact lists, erase-verification hook
    airlock/                  USB Airlock (D10): RED -> quarantine -> inspection -> approval -> GREEN
      structure.py            partition table, ESP, boot flags and boot code (worker, read-only fd)
      content.py              type from content, static script review, archive limits (no extraction)
      handlers.py             sandboxed workers: structure, content, ClamAV
      service.py              airlock.inspect / acquire / sessions / session / export / discard
    watchdog/                 watchdog boundary (D8): disabled adapter, pause-only effect
      adapter.py              Guardian's signal vocabulary and the adapter protocol
      pause.py                pause classes, watchdog.report / status / resume (owner touch)
    audit/                    tamper-evident audit ledger (handoff H1)
      ledger.py               hash-chained JSON-line segments, owner-signed checkpoints
      operations.py           audit.status / entries / verify / checkpoint
    deploy/                   Debian/MX installation (SysVinit only)
      debian.py               Guardian's own files: verified release, policy, init script
      preflight.py            read-only SysVinit preflight (PASS / PASS WITH FINDINGS / BLOCKED / UNKNOWN)
      inventory.py            dependency inventory derived from the code, package state
      bundle.py               owner-signed, target-specific, closed offline bundle
      installer.py            installer v2: plan (unprivileged), apply (root), validate, uninstall
      system.py               fixed-tool command runner, platform detection
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
(Debian 12, Python 3.11, SysVinit) is the reference target. Optional: `clamav` (Airlock; without it every file is
BLOCKED), `mount` (Airlock acquisition), `age` (capsules, deferred). `guardian.py inventory` lists every
dependency the code uses, with its class and installed state.

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

## Installing on Debian/MX (SysVinit only, offline)

On Guardian Main, build a deployment (one touch). On a machine of the
exact target (for example MX 23, Debian 12, amd64) with normal,
authenticated APT, download the packages the target lacks
(`apt-get download clamav ...`, with their dependencies). Then build the
offline bundle on Main (one touch; the key never leaves the YubiKey):

```
python3 -I -B guardian.py forge-build --socket S --auth guardian-key-a.pub guardian-key-a \
    --instance-id desk --platform debian-mx --profile storage --out desk.gpkg
python3 -I -B guardian.py bundle-build --deployment desk.gpkg --trust-log trust.log \
    --trust-anchor trust.anchor --debs ./debs --distribution mx --release 23 --debian 12 --arch amd64 \
    --auth guardian-key-a.pub guardian-key-a --out /media/rescue/desk-bundle
```

On the target, booted from the Rescue USB:

```
python3 -I -B guardian.py preflight                       # read-only; stops on systemd
python3 -I -B guardian.py install-plan --bundle desk-bundle --owner-uid 1000 --enable-service \
    --expect-anchor <anchor shown by trust-status on Main>
sudo python3 -I -B guardian.py install-apply --bundle desk-bundle --owner-uid 1000 --enable-service \
    --expect-anchor <anchor> --confirm <plan id>
# after an intentional reboot (the installer never reboots):
sudo python3 -I -B guardian.py install-validate --post-reboot
```

The plan shows platform, init, preflight, mode (INSTALL, VERIFY, REPAIR,
UPDATE), packages already satisfied and to install, and NONE for removals,
broad upgrades, bootloader, init conversion and systemd. Running it again
is safe. `uninstall-guardian --yes` removes Guardian's code and service and
keeps state, keys, data and configuration. The older single-step
`install-debian` remains for development.

## Device assurance (Stage 8)

```
python3 -I -B guardian.py devices --socket S                        # list, with fingerprints
python3 -I -B guardian.py assurance-device --socket S sdb           # what it exposes and what cannot be verified
python3 -I -B guardian.py erase-verify --socket S --auth KEY.pub HANDLE \
    --kname sdb --fingerprint FP --confirm sdb                      # DESTROYS sdb; writes a report
python3 -I -B guardian.py device-jobs --socket S                    # progress (another terminal)
python3 -I -B guardian.py report-sign --socket S --auth KEY.pub HANDLE REPORT_ID
python3 -I -B guardian.py report-export --socket S REPORT_ID --out report.json
python3 -I -B guardian.py report-verify report.json --trust-log trust.log --trust-anchor trust.anchor
python3 -I -B guardian.py artifacts-sign --list list.json --trust-anchor trust.anchor --auth KEY.pub HANDLE \
    --out artifacts.signed
python3 -I -B guardian.py artifacts-install --socket S artifacts.signed
python3 -I -B guardian.py artifact-verify --socket S mx-23.iso --name mx-23.iso
```

## USB Airlock (D10)

RED media is untrusted. Files move to GREEN media only through Guardian's
quarantine, never directly:

```
python3 -I -B guardian.py airlock-inspect --socket S sdb          # identity, BadUSB, partitions, verdict
python3 -I -B guardian.py airlock-acquire --socket S --auth KEY.pub HANDLE \
    --kname sdb --fingerprint FP --partition 1                    # read-only mount, copy, unmount, inspect
python3 -I -B guardian.py airlock-session --socket S SESSION      # states and findings per file
# detach RED, attach and mount GREEN, then:
python3 -I -B guardian.py airlock-inspect --socket S sdc          # GREEN fingerprint
python3 -I -B guardian.py airlock-export --socket S --auth KEY.pub HANDLE --session SESSION \
    --green-kname sdc --green-fingerprint FP --dest /media/green 1 2 [--acknowledge-review]
```

States: PASS, REVIEW_REQUIRED (exportable after acknowledging), BLOCKED,
MALWARE_DETECTED_BY_SCANNER, STRUCTURAL_ANOMALY, UNSUPPORTED_FILE_TYPE.
ClamAV (`clamav` package) is required: without it every file is BLOCKED.
A clean scan is one signal, not proof. Executables, disk and boot images
are blocked in this data-transfer mode. The export writes the files and
`airlock-manifest.json` (all hashes) into a new `GUARDIAN-AIRLOCK-<session>`
folder and reads every file back.

## Spinoff leases (D5)

An installed spinoff starts **UNLEASED**: it can verify and release
existing transfers, but intake, writing transfers and destructive device
work need an ACTIVE lease. Records travel on any media; only the owner
signature (one touch on Guardian Main) gives them weight.

```
# spinoff: make a request (generates the spinoff key on first use)
python3 -I -B guardian.py lease-request --socket S --out /media/usb/desk-request.json
# Guardian Main: check the printed key fingerprint and machine binding against
# the spinoff's screen, then touch the YubiKey (90 days unless --days says otherwise)
python3 -I -B guardian.py lease-issue --socket S --auth guardian-key-a.pub guardian-key-a \
    --request /media/usb/desk-request.json --out /media/usb/desk-lease.json
# spinoff
python3 -I -B guardian.py lease-import --socket S /media/usb/desk-lease.json
python3 -I -B guardian.py lease-status --socket S
```

- **Renewal:** the same three steps before expiry (state EXPIRING during the
  last 14 days by default).
- **Revocation:** `lease-revoke --instance-id desk --out FILE` on Main,
  then `lease-import FILE` on the spinoff. It takes effect at Main at once,
  but on an offline spinoff only when the record is imported or the lease
  expires. Nothing is erased.
- **Reissue** (lost or compromised spinoff key, reinstall): `lease-request
  --rekey` (or a fresh install) and `lease-issue --reissue`. The new
  generation has a fresh key; the old one becomes SUPERSEDED and Main
  refuses it from then on.
- **Reconnect:** `lease-check --request FILE --out RECORD` on Main tells
  whether a spinoff's generation is current, superseded or revoked, and
  writes the latest signed record for it to import.

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
plus the YubiKey `owner_key` factor (one touch), and on a spinoff an
ACTIVE lease.

Running the broker as a normal user is **development mode**. Workers then
share your uid. They still get the resource limits and process flags, but
they are not separated from your files. The broker prints a warning when it
starts this way.

The broker's role follows from its state directory: with the installer's
`deployment.json` it runs as a spinoff (lease gate on, no Forge or lease
issuing), without it as Guardian Main. On an installed system the SysVinit
script from `install-debian` starts it.

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
- **Stage 7:** a real signed deployment installed into temporary roots.
  Checked:
  - root-owned read-only release, atomic `current`, private trust state
  - policy, init script syntax, and a broker started from the installed code
  - production hardware-only policy enforced
  - tampered packages and a wrong anchor or platform refused without a trace
  - reinstall refused, switching releases with rollback kept
  - existing policy preserved, trust-log merge and fork refusal
  - dry run leaves nothing, and worker-account checks
- **Hygiene:** no `shell=True`, `eval`, `exec`, `pickle`, dynamic imports or
  unbounded reads; ASCII-only, licensed, stdlib-only sources.
