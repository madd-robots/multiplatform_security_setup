# Guardian USB Encryption Hub

A personal USB security and recovery platform. YubiKeys are the owner's root
of trust, and Guardian Main builds signed spinoffs for Debian/MX, Termux and
Windows. The full plan, stage status and the design changes made along the way
are in [ROADMAP.md](ROADMAP.md). Read [SECURITY_MODEL.md](SECURITY_MODEL.md)
for what the code guarantees today and what it does not.

**Status: Stages 1 and 2 of 9 are implemented.** The owner decisions in ROADMAP.md (integrity-first threat model, touch-only YubiKeys, dedicated drives) govern the remaining stages. There is no device analysis,
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

Requirements: Linux, Python 3.10 or newer, standard library only. MX Linux 23
(Debian 12, Python 3.11) is the reference target.

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
    --socket /run/usbguardian/broker.sock --socket-mode 600 \
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
```

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
- **Hygiene:** no `shell=True`, `eval`, `exec`, `pickle`, dynamic imports or
  unbounded reads; ASCII-only, licensed, stdlib-only sources.
