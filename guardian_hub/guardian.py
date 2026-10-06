#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian USB Encryption Hub command line.  Run with: python3 -I -B guardian.py

Broker (root, from the Rescue USB or installed system):
    guardian.py broker --policy FILE --socket PATH --state-dir DIR [--worker-user NAME]
                       [--instance-id ID] [--log-file FILE] [--lease-days N]

Owner keys (each signature needs a touch on the YubiKey; no PIN, no password):
    guardian.py key-info KEY.pub
    guardian.py trust-init   --socket S --owner KEY.pub HANDLE LABEL [--owner KEY.pub HANDLE LABEL]
    guardian.py trust-enroll --socket S --new KEY.pub HANDLE LABEL --auth KEY.pub HANDLE
    guardian.py trust-revoke --socket S --subject KEY_ID --auth KEY.pub HANDLE --reason TEXT
    guardian.py trust-status --socket S

Custody and transfers:
    guardian.py intake           --socket S --auth KEY.pub HANDLE FILE...
    guardian.py transfer-write   --socket S --auth KEY.pub HANDLE --out PACKAGE RECORD_ID...
    guardian.py transfer-verify  --socket S PACKAGE
    guardian.py transfer-release --socket S --auth KEY.pub HANDLE [--generate-names] PACKAGE DEST_DIR

Guardian Forge (Guardian Main):
    guardian.py forge-build  --socket S --auth KEY.pub HANDLE --instance-id ID --platform P --profile R --out PKG
                             [--redeploy]
    guardian.py forge-list   --socket S
    guardian.py forge-retire --socket S --auth KEY.pub HANDLE --instance-id ID

Offline leases (D5). Records travel on any media; trust comes from the owner signature:
    spinoff:  guardian.py lease-request --socket S --out REQUEST [--rekey]
              guardian.py lease-import  --socket S RECORD
              guardian.py lease-status  --socket S
    Main:     guardian.py lease-issue  --socket S --auth KEY.pub HANDLE --request REQUEST --out RECORD
                                       [--days N] [--warn-days N] [--reissue]
              guardian.py lease-revoke --socket S --auth KEY.pub HANDLE --instance-id ID --out RECORD
                                       [--reason TEXT]
              guardian.py lease-check  --socket S --request REQUEST [--out RECORD]

USB Airlock (RED -> quarantine -> inspection -> owner approval -> GREEN):
    guardian.py airlock-inspect  --socket S KNAME                 (also shows a GREEN device's fingerprint)
    guardian.py airlock-acquire  --socket S --auth KEY.pub HANDLE --kname K --fingerprint FP --partition N
                                 [--accept-review]
    guardian.py airlock-sessions --socket S
    guardian.py airlock-session  --socket S SESSION [--since N]
    guardian.py airlock-export   --socket S --auth KEY.pub HANDLE --session SESSION --green-kname K
                                 --green-fingerprint FP --dest DIR [--acknowledge-review] ITEM...
    guardian.py airlock-discard  --socket S --auth KEY.pub HANDLE SESSION

Watchdog pauses (D8; no watchdog adapter is enabled yet):
    guardian.py watchdog-status --socket S
    guardian.py watchdog-resume --socket S --auth KEY.pub HANDLE

Install on Debian/MX (root, from the Rescue USB):
    guardian.py install-debian --package PKG --trust-log trust.log --trust-anchor trust.anchor
                               --owner-uid UID --worker-user usbguardian-worker
                               [--platform debian-mx|rescue-usb] [--enable-service] [--replace-policy] [--dry-run]

Audit ledger:
    guardian.py audit-status     --socket S
    guardian.py audit-verify     --socket S
    guardian.py audit-checkpoint --socket S --auth KEY.pub HANDLE

Any operation:
    guardian.py call OP [--params JSON] [--auth KEY.pub HANDLE] --socket S
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pwd
import signal
import sys
from pathlib import Path
from typing import Any, List, Optional

# -I removes the script directory from sys.path; append (never prepend) it.
sys.path.append(str(Path(__file__).resolve().parent))

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common.canonical import canonical_dumps, canonical_loads  # noqa: E402
from usbguardian.common.errors import GuardianError, ValidationError  # noqa: E402
from usbguardian.common.fsutil import read_file_bounded  # noqa: E402
from usbguardian.common.log import configure_logging  # noqa: E402
from usbguardian.common.text import display_text  # noqa: E402
from usbguardian.identity import enrollment  # noqa: E402
from usbguardian.identity.owner import call_as_owner  # noqa: E402
from usbguardian.identity.sshkeys import parse_public_key  # noqa: E402
from usbguardian.identity.sshsig import NS_AUDIT, NS_DEPLOY, NS_LEASE, NS_TRANSFER, SshKeygenSigner  # noqa: E402
from usbguardian.runtime.authz import Policy  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.sandbox import make_non_dumpable  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.runtime.workers import WorkerLauncher  # noqa: E402


def _print(result: Any) -> None:
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))


def _signer(pub: str, handle: str) -> SshKeygenSigner:
    key = parse_public_key(read_file_bounded(Path(pub), 8192).decode("ascii", "replace"))
    return SshKeygenSigner(handle, key)


def _client(args: argparse.Namespace) -> BrokerClient:
    return BrokerClient(Path(args.socket), timeout=180.0)  # allow time for a touch


def _open_ro(path: str, directory: bool = False) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0)
    return os.open(path, flags)


def _close(fds: List[int]) -> None:
    for fd in fds:
        os.close(fd)


def cmd_broker(args: argparse.Namespace) -> int:
    configure_logging(Path(args.log_file) if args.log_file else None, level=logging.INFO)
    make_non_dumpable()
    euid = os.geteuid()
    owners = (0,) if euid == 0 else (0, euid)
    policy = Policy.load(Path(args.policy), allowed_owners=owners)
    uid = gid = None
    if args.worker_user:
        entry = pwd.getpwnam(args.worker_user)
        uid, gid = entry.pw_uid, entry.pw_gid
    launcher = WorkerLauncher(worker_uid=uid, worker_gid=gid)
    if euid != 0:
        print("WARNING: development mode. Workers run as your own user; the sandbox limits them but does not "
              "separate them from your files. Run the broker as root with --worker-user for real use.",
              file=sys.stderr)
    services = build_services(launcher, Path(args.state_dir), instance_id=args.instance_id,
                              lease_days=args.lease_days)
    print("Guardian broker: role %s, instance %s." % (services.role, args.instance_id), file=sys.stderr)
    server = BrokerServer(services.broker, policy, Path(args.socket), socket_mode=int(args.socket_mode, 8))
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    server.serve_forever()
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    params = canonical_loads(args.params.encode("utf-8")) if args.params else {}
    with _client(args) as client:
        if args.auth:
            _print(call_as_owner(client, _signer(*args.auth), args.op, params))
        else:
            _print(client.call(args.op, params))
    return 0


def cmd_key_info(args: argparse.Namespace) -> int:
    key = parse_public_key(read_file_bounded(Path(args.pub), 8192).decode("ascii", "replace"))
    _print({"key_id": key.key_id, "openssh_fingerprint": key.openssh_fingerprint, "key_type": key.key_type})
    return 0


def cmd_trust_init(args: argparse.Namespace) -> int:
    keys = [(_signer(pub, handle), label, None) for pub, handle, label in args.owner]
    print("Touch each YubiKey when it blinks (one touch per key).", file=sys.stderr)
    envelope = enrollment.genesis(keys)
    with _client(args) as client:
        _print(client.call("trust.init", {"envelope": envelope}))
    return 0


def _head(client: BrokerClient) -> "tuple[str, int]":
    status = client.call("trust.status")
    if not status.get("initialized"):
        raise ValidationError("trust is not initialized")
    return status["head"], status["seq"]


def cmd_trust_enroll(args: argparse.Namespace) -> int:
    with _client(args) as client:
        head, seq = _head(client)
        print("Touch the enrolled key, then the new key.", file=sys.stderr)
        envelope = enrollment.enroll(head, seq, _signer(args.new[0], args.new[1]), args.new[2], None,
                                     _signer(*args.auth))
        _print(client.call("trust.append", {"envelope": envelope}))
    return 0


def cmd_trust_revoke(args: argparse.Namespace) -> int:
    with _client(args) as client:
        head, seq = _head(client)
        envelope = enrollment.revoke(head, seq, args.subject, _signer(*args.auth), args.reason)
        _print(client.call("trust.append", {"envelope": envelope}))
    return 0


def cmd_trust_status(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("trust.status"))
    return 0


def cmd_intake(args: argparse.Namespace) -> int:
    fds = [_open_ro(path) for path in args.files]
    try:
        with _client(args) as client:
            _print(call_as_owner(client, _signer(*args.auth), "vault.intake",
                                 {"names": [os.path.basename(p) for p in args.files]}, fds))
    finally:
        _close(fds)
    return 0


def cmd_transfer_write(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    out = os.open(args.out, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with _client(args) as client:
            prepared = client.call("transfer.prepare", {"record_ids": args.records, "key_id": signer.key_id})
            if prepared["namespace"] != NS_TRANSFER:
                raise ValidationError("unexpected signing namespace")
            print("Touch the YubiKey to sign transfer %s." % prepared["transfer_id"], file=sys.stderr)
            signature = signer.sign_ns(NS_TRANSFER, bytes.fromhex(prepared["digest"]))
            _print(client.call("transfer.write", {"transfer_id": prepared["transfer_id"],
                                                  "signature": signature.decode("ascii")}, [out]))
    finally:
        os.close(out)
    return 0


def cmd_transfer_verify(args: argparse.Namespace) -> int:
    fd = _open_ro(args.package)
    try:
        with _client(args) as client:
            _print(client.call("transfer.verify", {"offset": 0}, [fd]))
    finally:
        os.close(fd)
    return 0


def cmd_transfer_release(args: argparse.Namespace) -> int:
    fds = [_open_ro(args.package), _open_ro(args.dest, directory=True)]
    try:
        with _client(args) as client:
            policy = "generate" if args.generate_names else "strict"
            _print(call_as_owner(client, _signer(*args.auth), "transfer.release", {"name_policy": policy}, fds))
    finally:
        _close(fds)
    return 0


def cmd_forge_build(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    out = os.open(args.out, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with _client(args) as client:
            prepared = client.call("forge.prepare", {"instance_id": args.instance_id, "platform": args.platform,
                                                     "profile": args.profile, "key_id": signer.key_id,
                                                     "redeploy": args.redeploy})
            if prepared["namespace"] != NS_DEPLOY:
                raise ValidationError("unexpected signing namespace")
            print("Deployment %s for %s (%s, profile %s, capabilities: %s)." % (
                prepared["deployment_id"], prepared["instance_id"], prepared["platform"], prepared["profile"],
                ", ".join(prepared["capabilities"])), file=sys.stderr)
            print("Touch the YubiKey to sign it.", file=sys.stderr)
            signature = signer.sign_ns(NS_DEPLOY, bytes.fromhex(prepared["digest"]))
            _print(client.call("forge.write", {"deployment_id": prepared["deployment_id"],
                                               "signature": signature.decode("ascii")}, [out]))
    finally:
        os.close(out)
    return 0


def cmd_forge_list(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("forge.list"))
    return 0


def cmd_forge_retire(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(call_as_owner(client, _signer(*args.auth), "forge.retire", {"instance_id": args.instance_id}))
    return 0


def _read_doc(path: str) -> Any:
    """A request or record from removable media: bounded, strict canonical JSON, untrusted until verified."""
    return canonical_loads(read_file_bounded(Path(path), 64 * 1024).rstrip(b"\n"), require_canonical=True,
                           max_bytes=64 * 1024)


def _write_doc(path: str, doc: Any) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.write(fd, canonical_dumps(doc) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_lease_status(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("lease.status"))
    return 0


def cmd_lease_request(args: argparse.Namespace) -> int:
    with _client(args) as client:
        result = client.call("lease.request", {"rekey": args.rekey})
    _write_doc(args.out, result["envelope"])
    print("Lease request written. Compare on Guardian Main before touching the YubiKey:\n"
          "  spinoff key %s\n  machine binding %s" % (result["key_fingerprint"], result["machine_id"]),
          file=sys.stderr)
    return 0


def cmd_lease_import(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("lease.import", {"envelope": _read_doc(args.record)}))
    return 0


def _sign_lease(client: BrokerClient, signer: SshKeygenSigner, params: Any, out: str) -> None:
    prepared = client.call("lease.prepare", dict(params, key_id=signer.key_id))
    if prepared["namespace"] != NS_LEASE:
        raise ValidationError("unexpected signing namespace")
    summary = {k: v for k, v in prepared.items() if k not in ("digest", "namespace")}
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True), file=sys.stderr)
    print("Check the key fingerprint and machine binding against the spinoff's screen, then touch the YubiKey.",
          file=sys.stderr)
    signature = signer.sign_ns(NS_LEASE, bytes.fromhex(prepared["digest"]))
    result = client.call("lease.commit", {"record_id": prepared["record_id"], "signature": signature.decode("ascii")})
    _write_doc(out, result["envelope"])
    _print({k: v for k, v in result.items() if k != "envelope"})


def cmd_lease_issue(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    request = _read_doc(args.request)
    instance = request.get("request", {}).get("instance_id") if isinstance(request, dict) else None
    if not isinstance(instance, str):
        raise ValidationError("not a lease request")
    params: Any = {"action": "issue", "instance_id": instance, "request": request, "reissue": args.reissue}
    if args.days is not None:
        params["days"] = args.days
    if args.warn_days is not None:
        params["warn_days"] = args.warn_days
    with _client(args) as client:
        _sign_lease(client, signer, params, args.out)
    return 0


def cmd_lease_revoke(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    with _client(args) as client:
        _sign_lease(client, signer, {"action": "revoke", "instance_id": args.instance_id, "reason": args.reason},
                    args.out)
    return 0


def cmd_lease_check(args: argparse.Namespace) -> int:
    with _client(args) as client:
        result = client.call("lease.check", {"request": _read_doc(args.request)})
    if args.out and result["latest"] is not None:
        _write_doc(args.out, result["latest"])
    _print({k: v for k, v in result.items() if k != "latest"})
    return 0


def cmd_airlock_inspect(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("airlock.inspect", {"kname": args.kname}))
    return 0


def cmd_airlock_acquire(args: argparse.Namespace) -> int:
    print("Touch the YubiKey to mount %s partition %d read-only and copy its files into quarantine."
          % (args.kname, args.partition), file=sys.stderr)
    with _client(args) as client:
        _print(call_as_owner(client, _signer(*args.auth), "airlock.acquire",
                             {"kname": args.kname, "fingerprint": args.fingerprint, "partition": args.partition,
                              "accept_review": args.accept_review}))
    return 0


def cmd_airlock_sessions(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("airlock.sessions"))
    return 0


def cmd_airlock_session(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("airlock.session", {"session_id": args.session, "since": args.since, "limit": 128}))
    return 0


def cmd_airlock_export(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    wanted = set(args.items)
    dest = _open_ro(args.dest, directory=True)
    try:
        with _client(args) as client:
            chosen, since = [], 0
            while True:
                page = client.call("airlock.session", {"session_id": args.session, "since": since, "limit": 128})
                for it in page["items_page"]:
                    if it["item"] in wanted:
                        chosen.append(it)
                if len(page["items_page"]) < 128:
                    break
                since += 128
            if {it["item"] for it in chosen} != wanted:
                raise ValidationError("unknown item ids: %s" % sorted(wanted - {it["item"] for it in chosen}))
            print("Approving for export to %s (%s):" % (args.green_kname, args.green_fingerprint), file=sys.stderr)
            for it in chosen:
                print("  #%d %s  %s  %s  sha256 %s" % (it["item"], it["state"], it["type"],
                                                       display_text(it["source_path"], 120), it["sha256"]),
                      file=sys.stderr)
            print("Touch the YubiKey to approve exactly these files.", file=sys.stderr)
            params = {"session_id": args.session, "green_kname": args.green_kname,
                      "green_fingerprint": args.green_fingerprint, "acknowledge_review": args.acknowledge_review,
                      "items": [{"item": it["item"], "sha256": it["sha256"]} for it in chosen]}
            _print(call_as_owner(client, signer, "airlock.export", params, [dest]))
    finally:
        os.close(dest)
    return 0


def cmd_airlock_discard(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(call_as_owner(client, _signer(*args.auth), "airlock.discard", {"session_id": args.session}))
    return 0


def cmd_watchdog_status(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("watchdog.status"))
    return 0


def cmd_watchdog_resume(args: argparse.Namespace) -> int:
    with _client(args) as client:
        status = client.call("watchdog.status")
        print("Paused: %s (%s). Touch the YubiKey to resume." % (", ".join(status["paused"]) or "nothing",
                                                                 display_text(status["reason"], 300)),
              file=sys.stderr)
        _print(call_as_owner(client, _signer(*args.auth), "watchdog.resume", {}))
    return 0


def cmd_install_debian(args: argparse.Namespace) -> int:
    from usbguardian.deploy.debian import install_debian
    from usbguardian.identity.handlers import WorkerSigCheck

    entry = pwd.getpwnam(args.worker_user)
    sig_check = WorkerSigCheck(WorkerLauncher(worker_uid=entry.pw_uid, worker_gid=entry.pw_gid))
    _print(install_debian(Path(args.package), Path(args.trust_log), Path(args.trust_anchor),
                          owner_uid=args.owner_uid, worker_user=args.worker_user, sig_check=sig_check,
                          platform=args.platform, replace_policy=args.replace_policy,
                          enable_service=args.enable_service, dry_run=args.dry_run))
    return 0


def cmd_audit_status(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("audit.status"))
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    with _client(args) as client:
        _print(client.call("audit.verify"))
    return 0


def cmd_audit_checkpoint(args: argparse.Namespace) -> int:
    signer = _signer(*args.auth)
    with _client(args) as client:
        status = client.call("audit.status")
        if status["namespace"] != NS_AUDIT:
            raise ValidationError("unexpected signing namespace")
        print("Touch the YubiKey to sign audit checkpoint at entry %d." % status["head_seq"], file=sys.stderr)
        signature = signer.sign_ns(NS_AUDIT, bytes.fromhex(status["checkpoint_digest"]))
        _print(client.call("audit.checkpoint", {"seq": status["head_seq"], "hash": status["head"],
                                                "key_id": signer.key_id, "signature": signature.decode("ascii")}))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name: str, func: Any, help_text: str, socket: bool = True) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        if socket:
            p.add_argument("--socket", required=True)
        p.set_defaults(func=func)
        return p

    b = command("broker", cmd_broker, "run the broker")
    b.add_argument("--policy", required=True)
    b.add_argument("--state-dir", required=True)
    b.add_argument("--instance-id", default="guardian-main")
    b.add_argument("--socket-mode", default="600")
    b.add_argument("--worker-user")
    b.add_argument("--log-file")
    b.add_argument("--lease-days", type=int, default=90, help="Main: default lease length in days (policy)")
    c = command("call", cmd_call, "call a broker operation")
    c.add_argument("op")
    c.add_argument("--params")
    c.add_argument("--auth", nargs=2, metavar=("KEY_PUB", "HANDLE"))
    k = command("key-info", cmd_key_info, "show a public key's id and fingerprint", socket=False)
    k.add_argument("pub")
    t = command("trust-init", cmd_trust_init, "enroll the owner keys (genesis)")
    t.add_argument("--owner", nargs=3, action="append", required=True, metavar=("KEY_PUB", "HANDLE", "LABEL"))
    t = command("trust-enroll", cmd_trust_enroll, "enroll a replacement key")
    t.add_argument("--new", nargs=3, required=True, metavar=("KEY_PUB", "HANDLE", "LABEL"))
    t.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    t = command("trust-revoke", cmd_trust_revoke, "revoke a lost or retired key")
    t.add_argument("--subject", required=True)
    t.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    t.add_argument("--reason", default="")
    command("trust-status", cmd_trust_status, "show enrolled keys")
    i = command("intake", cmd_intake, "take files into custody")
    i.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    i.add_argument("files", nargs="+")
    w = command("transfer-write", cmd_transfer_write, "write a signed transfer package")
    w.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    w.add_argument("--out", required=True)
    w.add_argument("records", nargs="+")
    v = command("transfer-verify", cmd_transfer_verify, "verify a transfer package")
    v.add_argument("package")
    r = command("transfer-release", cmd_transfer_release, "verify and release a transfer package")
    r.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    r.add_argument("--generate-names", action="store_true")
    r.add_argument("package")
    r.add_argument("dest")

    f = command("forge-build", cmd_forge_build, "build and sign a spinoff deployment")
    f.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    f.add_argument("--instance-id", required=True)
    f.add_argument("--platform", required=True)
    f.add_argument("--profile", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--redeploy", action="store_true", help="new package for an existing instance (code update)")
    command("forge-list", cmd_forge_list, "list deployments built by this Guardian Main")
    f = command("forge-retire", cmd_forge_retire, "retire a deployment at Guardian Main")
    f.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    f.add_argument("--instance-id", required=True)

    command("lease-status", cmd_lease_status, "spinoff: show the lease state")
    q = command("lease-request", cmd_lease_request, "spinoff: write a signed lease request")
    q.add_argument("--out", required=True)
    q.add_argument("--rekey", action="store_true", help="fresh key for a reissue (generation N+1)")
    q = command("lease-import", cmd_lease_import, "spinoff: import a signed lease or revocation")
    q.add_argument("record")
    q = command("lease-issue", cmd_lease_issue, "Main: issue or renew a lease from a request")
    q.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    q.add_argument("--request", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--days", type=int)
    q.add_argument("--warn-days", type=int)
    q.add_argument("--reissue", action="store_true", help="confirm a new key (generation N+1)")
    q = command("lease-revoke", cmd_lease_revoke, "Main: revoke a spinoff's current generation")
    q.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    q.add_argument("--instance-id", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--reason", default="")
    q = command("lease-check", cmd_lease_check, "Main: check a spinoff's request against the registry")
    q.add_argument("--request", required=True)
    q.add_argument("--out")
    a = command("airlock-inspect", cmd_airlock_inspect, "inspect a RED (or GREEN) device")
    a.add_argument("kname")
    a = command("airlock-acquire", cmd_airlock_acquire, "acquire a RED volume into quarantine (touch)")
    a.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    a.add_argument("--kname", required=True)
    a.add_argument("--fingerprint", required=True)
    a.add_argument("--partition", type=int, required=True, help="partition index, 0 for a whole-device filesystem")
    a.add_argument("--accept-review", action="store_true")
    command("airlock-sessions", cmd_airlock_sessions, "list airlock sessions")
    a = command("airlock-session", cmd_airlock_session, "show a session's items and findings")
    a.add_argument("session")
    a.add_argument("--since", type=int, default=0)
    a = command("airlock-export", cmd_airlock_export, "approve items and export them to GREEN (touch)")
    a.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    a.add_argument("--session", required=True)
    a.add_argument("--green-kname", required=True)
    a.add_argument("--green-fingerprint", required=True)
    a.add_argument("--dest", required=True, help="directory on the mounted GREEN device")
    a.add_argument("--acknowledge-review", action="store_true")
    a.add_argument("items", nargs="+", type=int)
    a = command("airlock-discard", cmd_airlock_discard, "delete a session's quarantine copies (touch)")
    a.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    a.add_argument("session")
    command("watchdog-status", cmd_watchdog_status, "show watchdog pauses and recent signals")
    w = command("watchdog-resume", cmd_watchdog_resume, "lift watchdog pauses (owner touch)")
    w.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    command("audit-status", cmd_audit_status, "show the audit ledger head")
    command("audit-verify", cmd_audit_verify, "verify the audit chain and signed checkpoints")
    a = command("audit-checkpoint", cmd_audit_checkpoint, "sign a checkpoint of the audit ledger head")
    a.add_argument("--auth", nargs=2, required=True, metavar=("KEY_PUB", "HANDLE"))
    d = command("install-debian", cmd_install_debian, "install a verified deployment on Debian/MX", socket=False)
    d.add_argument("--package", required=True)
    d.add_argument("--trust-log", required=True)
    d.add_argument("--trust-anchor", required=True)
    d.add_argument("--owner-uid", type=int, required=True)
    d.add_argument("--worker-user", required=True)
    d.add_argument("--platform", default="debian-mx", choices=["debian-mx", "rescue-usb"])
    d.add_argument("--enable-service", action="store_true")
    d.add_argument("--replace-policy", action="store_true")
    d.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GuardianError as exc:
        print("ERROR %s: %s" % (exc.code, display_text(exc.message, 500)), file=sys.stderr)
        return 2
    except (OSError, KeyError, ValueError) as exc:
        print("ERROR: %s" % display_text(exc, 500), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
