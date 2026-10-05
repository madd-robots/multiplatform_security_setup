#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian USB Encryption Hub command line.  Run with: python3 -I -B guardian.py

    guardian.py broker --policy FILE --socket PATH [--worker-user NAME] [--log-file FILE]
    guardian.py call OP [--params JSON] --socket PATH
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

# -I removes the script directory from sys.path; append (never prepend) it.
sys.path.append(str(Path(__file__).resolve().parent))

from usbguardian.common.canonical import canonical_loads  # noqa: E402
from usbguardian.common.errors import GuardianError  # noqa: E402
from usbguardian.common.log import configure_logging  # noqa: E402
from usbguardian.common.text import display_text  # noqa: E402
from usbguardian.runtime.authz import Policy  # noqa: E402
from usbguardian.runtime.broker import Broker, default_operations  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.sandbox import make_non_dumpable  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.runtime.workers import WorkerLauncher  # noqa: E402


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
    server = BrokerServer(Broker(default_operations(), launcher), policy, Path(args.socket),
                          socket_mode=int(args.socket_mode, 8))
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    server.serve_forever()
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    params = canonical_loads(args.params.encode("utf-8")) if args.params else {}
    with BrokerClient(Path(args.socket)) as client:
        result = client.call(args.op, params)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("broker", help="run the broker")
    b.add_argument("--policy", required=True)
    b.add_argument("--socket", required=True)
    b.add_argument("--socket-mode", default="600")
    b.add_argument("--worker-user")
    b.add_argument("--log-file")
    b.set_defaults(func=cmd_broker)
    c = sub.add_parser("call", help="call a broker operation")
    c.add_argument("op")
    c.add_argument("--params")
    c.add_argument("--socket", required=True)
    c.set_defaults(func=cmd_call)
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
