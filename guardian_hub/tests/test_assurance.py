# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 8 tests: assurance facts, drive registry, reports (ledger, signatures, export), artifacts, erase hook."""

import copy
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_devices import MIB, FakeSys  # noqa: E402
from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.assurance.drives import DriveRegistry  # noqa: E402
from usbguardian.assurance.facts import analyse  # noqa: E402
from usbguardian.assurance.reports import ReportStore, verify_export  # noqa: E402
from usbguardian.assurance.service import AssuranceService, artifact_list_digest  # noqa: E402
from usbguardian.audit.ledger import AuditLedger  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.devices.handlers import build_report  # noqa: E402
from usbguardian.devices.identity import fingerprint  # noqa: E402
from usbguardian.devices.operations import JobTracker  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.trust import TrustStore  # noqa: E402
from usbguardian.identity.sshsig import NS_ARTIFACTS, NS_REPORT, NS_TRANSFER, tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.broker import Broker  # noqa: E402
from usbguardian.runtime.session import Session  # noqa: E402


def codes(findings):
    return {f["code"] for f in findings}


class Devices:
    def __init__(self, root):
        self.fs = FakeSys(root)

    def report(self, **kw):
        self.fs.add_usb(**kw)
        return build_report(self.fs.scanner().inspect(kw.get("kname", "sdb")))


def changed(report, **usb):
    r = copy.deepcopy(report)
    r["device"]["usb"].update(usb)
    r["fingerprint"] = fingerprint(r["device"])
    return r


class FactsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dev = Devices(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_and_inconsistent_devices(self):
        clean = analyse(self.dev.report()["device"])
        self.assertFalse([f for f in clean["findings"] if f["severity"] != "INFO"], clean["findings"])
        self.assertEqual(clean["firmware_indicators"]["usb_bcd_device"], "0100")
        self.assertIn("controller firmware", clean["not_verifiable"][0])
        fake = analyse(self.dev.report(kname="sdc", port="2-2", devnum="8:32", sectors=8192, serial="000000",
                                       product="Ultra 64GB")["device"])
        self.assertTrue({"WEAK_SERIAL", "CAPACITY_DISAGREES_WITH_LABEL"} <= codes(fake["findings"]))
        dev = self.dev.report(kname="sdd", port="2-3", devnum="8:48")["device"]
        dev["usb"]["usb_version"], dev["usb"]["speed"] = "3.20", "480"
        dev["physical_block_size"] = 256
        self.assertTrue({"RUNNING_BELOW_USB3", "BLOCK_SIZES_INCONSISTENT"} <= codes(analyse(dev)["findings"]))


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.reg = DriveRegistry(root / "drives")
        self.report = Devices(root / "sys").report()

    def tearDown(self):
        self.tmp.cleanup()

    def test_known_changed_rejected(self):
        dev, fp = self.report["device"], self.report["fingerprint"]
        self.assertEqual(self.reg.check(dev, fp), ("UNKNOWN", []))
        self.reg.record_verified(dev, fp, "a" * 24)
        self.assertEqual(self.reg.check(dev, fp)[0], "KNOWN")
        new_fw = changed(self.report, bcd_device="0200")  # same vendor, product and serial
        status, diffs = self.reg.check(new_fw["device"], new_fw["fingerprint"])
        self.assertEqual(status, "CHANGED")
        self.assertTrue(any("bcd_device" in d for d in diffs), diffs)
        self.assertEqual(self.reg.check(dev, fp)[0], "REJECTED")  # stays rejected
        self.assertEqual(self.reg.record_verified(dev, fp, "b" * 24)["state"], "rejected")  # no re-admission
        other = changed(self.report, serial="FFFF0002")
        self.assertEqual(self.reg.check(other["device"], other["fingerprint"])[0], "UNKNOWN")


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        kd = Path(cls._keys.name)
        cls.A, cls.X = _keygen(kd, "a"), _keygen(kd, "x")

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def setUp(self):
        from test_runtime import launcher
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        (root / "trust").mkdir(mode=0o700)
        self.trust = TrustStore(root / "trust", tool_verify, allowed_types=TEST_TYPES)
        self.trust.append(EN.genesis([(self.A, "A", None)]))
        self.audit = AuditLedger(root / "audit")
        self.devices = {"sdb": Devices(root / "sys").report()}
        self.svc = AssuranceService(root / "assurance", self.trust, tool_verify, "guardian-main", audit=self.audit,
                                    inspect_device=lambda k: self.devices[k])
        self.broker = Broker(self.svc.operations(), launcher(), audit=self.audit)
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, op, params, fds=(), factors=("peer_uid",)):
        self.n += 1
        session = Session(0, 0, 1)
        session.fds = list(fds)
        principal = authz.Principal("owner", 0, frozenset(authz.CAPABILITIES), frozenset(factors))
        req = {"v": 1, "type": "request", "id": "r%d" % self.n, "op": op, "params": params}
        if fds:
            req["fds"] = len(fds)
        resp = self.broker.handle(principal, req, session)
        session.close_fds()
        if not resp["ok"]:
            raise E.error_from_wire(resp["error"])
        return resp["result"]

    def test_device_report_erase_and_reinsertion(self):
        first = self.call("assurance.device", {"kname": "sdb"})
        self.assertEqual((first["result"], first["body"]["registry"]), ("PASS", "UNKNOWN"))
        report = self.devices["sdb"]
        result = {"size_bytes": 4 * MIB, "chunk_size": MIB, "chunks": 4, "direct_io": True, "bytes_written": 4 * MIB,
                  "write_error_offset": None, "bad_chunks": 0, "unreadable_chunks": 0, "bad_ranges": [],
                  "bad_ranges_truncated": False, "first_bad_offset": None, "verified_bytes": 4 * MIB,
                  "cancelled": False, "passed": True, "seconds": 3}
        erase = self.svc.erase_hook("owner", report, result, report)
        self.assertEqual(erase["registry"], "verified")
        stored = self.call("assurance.report", {"report_id": erase["report_id"]})
        self.assertEqual((stored["report"]["kind"], stored["report"]["result"], stored["ledger_match"]),
                         ("erase_verification", "PASSED", True))
        self.assertIn("not reached", " ".join(stored["report"]["statement"]))
        failed = self.svc.erase_hook("owner", report, dict(result, passed=False, bad_chunks=1), report)
        self.assertIsNone(failed["registry"])
        self.assertEqual(self.call("assurance.device", {"kname": "sdb"})["body"]["registry"], "KNOWN")
        self.devices["sdb"] = changed(report, bcd_device="0900")  # firmware now reports another revision
        again = self.call("assurance.device", {"kname": "sdb"})
        self.assertEqual(again["result"], "BLOCKED")
        self.assertIn("IDENTITY_CHANGED_SINCE_VERIFIED", codes(again["body"]["findings"]))
        listed = self.call("assurance.reports", {"since": 0, "limit": 64})["reports"]
        self.assertEqual(len(listed), 5)

    def test_signing_export_and_tamper_detection(self):
        rid = self.call("assurance.device", {"kname": "sdb"})["report_id"]
        entry = self.call("assurance.report", {"report_id": rid})
        digest = bytes.fromhex(entry["digest"])
        for signer, ns in ((self.X, NS_REPORT), (self.A, NS_TRANSFER)):
            with self.assertRaises(E.PermissionDenied):  # outsider key, or the wrong namespace: no owner proof
                self.call("assurance.sign", {"report_id": rid, "key_id": signer.key_id,
                                             "signature": signer.sign_ns(ns, digest).decode()})
        self.call("assurance.sign", {"report_id": rid, "key_id": self.A.key_id,
                                     "signature": self.A.sign_ns(NS_REPORT, digest).decode()})
        export = self.call("assurance.report", {"report_id": rid})
        out = verify_export({"report": export["report"], "signatures": export["signatures"]},
                            self.trust.envelopes(), self.trust.require_state().anchor, tool_verify,
                            allowed_types=TEST_TYPES)
        self.assertEqual(out["signed_by"], [self.A.key_id])
        forged = dict(export["report"], result="PASS")
        forged["body"] = dict(forged["body"], registry="KNOWN")
        with self.assertRaises(E.IntegrityError):
            verify_export({"report": forged, "signatures": export["signatures"]}, self.trust.envelopes(),
                          self.trust.require_state().anchor, tool_verify, allowed_types=TEST_TYPES)
        path = self.root / "assurance" / "reports" / (rid + ".json")
        path.write_bytes(path.read_bytes().replace(b'"PASS"', b'"pass"'))
        os.chmod(path, 0o600)
        with self.assertRaises(E.GuardianError):
            self.call("assurance.report", {"report_id": rid})  # result must match the schema
        rid2 = self.call("assurance.device", {"kname": "sdb"})["report_id"]
        path2 = self.root / "assurance" / "reports" / (rid2 + ".json")
        path2.write_bytes(path2.read_bytes().replace(b'"0100"', b'"0101"'))
        self.assertFalse(self.call("assurance.report", {"report_id": rid2})["ledger_match"])

    def test_artifact_verification(self):
        data = self.root / "mx.iso"
        data.write_bytes(b"pretend installer image" * 1000)
        sha = hashlib.sha256(data.read_bytes()).hexdigest()
        doc = {"format": "guardian-artifact-list", "version": 1, "trust_anchor": self.trust.require_state().anchor,
               "created": "2026-10-07T00:00:00Z",
               "artifacts": [{"name": "mx-23.iso", "sha256": sha, "size": data.stat().st_size, "note": "checked"},
                             {"name": "other.bin", "sha256": "0" * 64, "size": 1, "note": ""}]}

        def envelope(signer):
            return {"list": doc, "key_id": signer.key_id,
                    "signature": signer.sign_ns(NS_ARTIFACTS, artifact_list_digest(doc)).decode()}

        def verify(name=None):
            fd = os.open(data, os.O_RDONLY)
            return self.call("assurance.artifact_verify", {"name": name} if name else {}, fds=[fd])["result"]
        with self.assertRaises(E.GuardianError) as cm:
            verify()
        self.assertEqual(cm.exception.code, "NO_ARTIFACT_LIST")
        with self.assertRaises(E.PermissionDenied):
            self.call("assurance.artifacts_set", {"envelope": envelope(self.X)})
        self.call("assurance.artifacts_set", {"envelope": envelope(self.A)})
        self.assertEqual(verify(), "VERIFIED")
        self.assertEqual(verify("mx-23.iso"), "VERIFIED")
        self.assertEqual(verify("other.bin"), "MISMATCH")
        data.write_bytes(data.read_bytes() + b"!")
        self.assertEqual(verify(), "NOT LISTED")


    def test_cli_signs_an_artifact_list(self):
        import contextlib
        import io
        import json
        import guardian
        listing = self.root / "list.json"
        listing.write_text(json.dumps([{"name": "tool.bin", "sha256": "a" * 64, "size": 3, "note": "from vendor"}]))
        out = self.root / "artifacts.signed"
        with contextlib.redirect_stderr(io.StringIO()):
            code = guardian.main(["artifacts-sign", "--list", str(listing), "--trust-anchor",
                                  str(self.root / "trust" / "trust.anchor"), "--auth", self.A.handle_path + ".pub",
                                  self.A.handle_path, "--out", str(out)])
        self.assertEqual(code, 0)
        envelope = guardian._read_doc_large(str(out))
        self.assertEqual(self.call("assurance.artifacts_set", {"envelope": envelope})["artifacts"], 1)
        self.assertEqual(self.call("assurance.artifacts", {})["list"]["artifacts"][0]["name"], "tool.bin")


class JobTests(unittest.TestCase):
    def test_progress_and_cancel(self):
        jobs = JobTracker(clock=lambda: 100.0)
        jobs.start("sdb", "f" * 64, 4 * MIB)
        with self.assertRaises(E.SecurityViolation):
            jobs.start("sdb", "f" * 64, 4 * MIB)
        jobs.progress("sdb", "write", MIB, 4 * MIB)
        self.assertEqual(jobs.snapshot()[0]["done"], MIB)
        self.assertFalse(jobs.should_stop("sdb"))
        self.assertTrue(jobs.cancel("sdb"))
        self.assertTrue(jobs.should_stop("sdb"))
        jobs.finish("sdb")
        self.assertEqual(jobs.snapshot(), [])
        self.assertFalse(jobs.cancel("sdb"))


if __name__ == "__main__":
    unittest.main()
