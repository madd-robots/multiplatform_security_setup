# SPDX-License-Identifier: GPL-3.0-or-later
"""Screens as pure functions: broker data -> lines of printable ASCII.

Device names, labels, file names and every other string that hostile
media can supply pass through ``display_text`` before they reach the
terminal, so escape sequences, bidi controls and control characters are
shown escaped and cannot redraw or spoof the screen. Every line is cut to
the terminal width.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ..common.text import display_text
from .model import ORDER

Data = Dict[str, Dict[str, Any]]
TITLES = {"dashboard": "Dashboard", "devices": "Devices", "keys": "Owner keys", "vault": "Custody",
          "airlock": "Airlock", "forge": "Forge / lease", "reports": "Reports", "audit": "Audit", "watchdog": "Watchdog"}
KEYS = {
    "dashboard": "r refresh",
    "devices": "up/down select  a assurance report  e erase-verify  c cancel erase",
    "keys": "r refresh",
    "vault": "up/down select",
    "airlock": "up/down select  enter items",
    "forge": "r refresh",
    "reports": "up/down select  enter details  s sign",
    "audit": "pgup/pgdn page  v verify chain  k checkpoint",
    "watchdog": "R resume (owner touch)",
}


def t(value: Any, limit: int = 200) -> str:
    """Untrusted value -> printable ASCII."""
    return display_text("" if value is None else value, limit)


def size_h(n: Optional[int]) -> str:
    if not isinstance(n, int):
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024  # type: ignore[assignment]
    return "?"


def bar(done: int, total: int, width: int = 30) -> str:
    frac = 0.0 if not total else max(0.0, min(1.0, done / total))
    filled = int(frac * width)
    return "[" + "#" * filled + "." * (width - filled) + "] %3d%%" % int(frac * 100)


def short(h: Any, n: int = 12) -> str:
    return t(h, 80)[:n]


def unavailable(section: Dict[str, Any]) -> Optional[str]:
    return None if section.get("ok") else "(%s)" % t(section.get("message"), 120)


def result(data: Data, name: str) -> Any:
    sec = data.get(name) or {}
    return sec.get("result") if sec.get("ok") else None


def tabs(current: str) -> str:
    return " ".join(("[%d %s]" if s == current else " %d %s ") % (i + 1, TITLES[s]) for i, s in enumerate(ORDER))


def dashboard(data: Data, **_: Any) -> List[str]:
    out = []
    st = result(data, "status")
    if st:
        out.append("Guardian %s  principal %s  capabilities %d" % (t(st["version"]), t(st["principal"]),
                                                                  len(st["capabilities"])))
    else:
        out.append("Broker status " + (unavailable(data["status"]) or ""))
    tr = result(data, "trust")
    if tr and tr.get("initialized"):
        labels = ", ".join(t(k["label"], 32) for k in tr["active"])
        out.append("Owner keys: %d active (%s), %d revoked; anchor %s" % (len(tr["active"]), labels,
                                                                           len(tr["revoked"]), short(tr["anchor"], 16)))
    else:
        out.append("Owner keys: " + ("not enrolled" if tr else unavailable(data["trust"]) or ""))
    lease, forge = result(data, "lease"), result(data, "forge")
    if lease:
        out.append("Role: spinoff  lease %s  until %s  (%s)" % (lease["state"], t(lease["not_after"]),
                                                               t(lease["reason"], 80)))
    elif forge is not None:
        out.append("Role: Guardian Main  deployments %d" % len(forge["deployments"]))
    wd = result(data, "watchdog")
    if wd:
        out.append("Watchdog: %s; paused: %s" % ("adapter " + t(wd["adapter"]) if wd["enabled"] else "disabled",
                                                ", ".join(wd["paused"]) or "nothing"))
    au = result(data, "audit")
    if au:
        out.append("Audit ledger: %d entries, head %s" % (au["head_seq"] + 1, short(au["head"], 16)))
    dv, jobs = result(data, "devices"), result(data, "jobs")
    if dv is not None:
        out.append("Devices: %d block devices, %d usable as Guardian media" % (
            len(dv["devices"]), sum(1 for d in dv["devices"] if d["candidate"])))
    for job in (jobs or {}).get("jobs", []):
        out.append("  erase-verify %s %s %s" % (t(job["kname"], 16), job["phase"], bar(job["done"], job["total"])))
    al = result(data, "airlock")
    if al is not None:
        out.append("Airlock sessions: %d" % len(al["sessions"]))
    rp = result(data, "reports")
    if rp is not None:
        out.append("Recent reports:")
        for r in rp["reports"][-5:]:
            out.append("  %s %-20s %s" % (t(r.get("created")), t(r.get("kind"), 20), t(r.get("result"))))
    return out


def devices(data: Data, selected: int = 0, **_: Any) -> List[str]:
    dv = result(data, "devices")
    if dv is None:
        return ["Devices " + (unavailable(data["devices"]) or "")]
    out = ["   %-8s %-6s %10s  %-9s %-28s %s" % ("device", "bus", "size", "usb id", "vendor / model", "status")]
    for i, d in enumerate(dv["devices"]):
        status = "usable" if d["candidate"] else "BLOCKED: " + ", ".join(t(b, 30) for b in d["blocking"][:3])
        out.append("%s %-8s %-6s %10s  %-9s %-28s %s" % (">" if i == selected else " ", t(d["kname"], 8),
                                                       t(d["transport"], 6), size_h(d["size_bytes"]),
                                                       t(d["usb_id"], 9),
                                                       (t(d["vendor"], 14) + " " + t(d["model"], 14))[:28], status))
    if dv["devices"] and 0 <= selected < len(dv["devices"]):
        out.append("")
        out.append("fingerprint %s" % t(dv["devices"][selected]["fingerprint"], 64))
    jobs = (result(data, "jobs") or {}).get("jobs", [])
    if jobs:
        out.append("")
        out.append("Running erase-verifications:")
        for j in jobs:
            out.append("  %s %-7s %s%s" % (t(j["kname"], 8), t(j["phase"], 7), bar(j["done"], j["total"]),
                                           "  cancelling" if j.get("cancelling") else ""))
    drives = result(data, "drives")
    if drives is not None:
        out.append("")
        out.append("Registry: %d verified drive(s), %d rejected" % (
            sum(1 for d in drives["drives"] if d["state"] == "verified"),
            sum(1 for d in drives["drives"] if d["state"] == "rejected")))
    return out


def keys(data: Data, **_: Any) -> List[str]:
    tr = result(data, "trust")
    if tr is None:
        return ["Owner keys " + (unavailable(data["trust"]) or "")]
    if not tr.get("initialized"):
        return ["No owner keys enrolled. Enroll both YubiKeys from the Rescue USB (trust-init)."]
    out = ["Trust anchor %s   log entries %d" % (t(tr["anchor"], 64), tr["seq"] + 1), "", "Active:"]
    for k in tr["active"]:
        out.append("  %-16s %-34s %s" % (t(k["label"], 16), t(k["key_type"], 34), t(k["openssh_fingerprint"], 60)))
    out.append("Revoked:")
    for k in tr["revoked"] or [{"key_id": "none", "revoked_seq": None}]:
        out.append("  %s%s" % (short(k["key_id"], 40), "" if k["revoked_seq"] is None else
                               "  (log entry %d)" % k["revoked_seq"]))
    out += ["", "Either active key alone authorizes owner operations; each needs a touch."]
    return out


def vault(data: Data, selected: int = 0, **_: Any) -> List[str]:
    rec = result(data, "records")
    if rec is None:
        return ["Custody " + (unavailable(data["records"]) or "")]
    out = ["%d record(s) in custody" % rec["total"], "   %-20s %10s  %-14s %s" % ("intake (UTC)", "size", "sha256",
                                                                               "source name (as data)")]
    for i, r in enumerate(rec["records"]):
        out.append("%s %-20s %10s  %-14s %s" % (">" if i == selected else " ", t(r["intake_time"], 20),
                                               size_h(r["length"]), short(r["sha256"]), t(r["source_name"], 80)))
    if rec["records"] and 0 <= selected < len(rec["records"]):
        out += ["", "record %s" % t(rec["records"][selected]["record_id"], 32)]
    return out


def airlock(data: Data, selected: int = 0, detail: Optional[Dict[str, Any]] = None, **_: Any) -> List[str]:
    al = result(data, "airlock")
    if al is None:
        return ["Airlock " + (unavailable(data["airlock"]) or "")]
    out = ["   %-26s %-11s %6s %7s  %s" % ("session", "state", "items", "skipped", "states")]
    for i, s in enumerate(al["sessions"]):
        states = ", ".join("%s %d" % (t(k, 30), v) for k, v in sorted((s.get("states") or {}).items()))
        out.append("%s %-26s %-11s %6s %7s  %s" % (">" if i == selected else " ", t(s["session_id"], 26),
                                                   t(s.get("state"), 11), s.get("items", ""), s.get("skipped", ""),
                                                   states))
    if detail:
        out += ["", "Items of %s:" % t(detail.get("session_id"), 26)]
        for it in detail.get("items_page", []):
            out.append("  #%-4d %-28s %-22s %8s  %s" % (it["item"], t(it["state"], 28), t(it["type"], 22),
                                                       size_h(it["size"]), t(it["source_path"], 70)))
        out.append("Export with: guardian.py airlock-export ... (the GREEN directory is opened by you, not the UI)")
    return out


def forge(data: Data, **_: Any) -> List[str]:
    lease, fg = result(data, "lease"), result(data, "forge")
    if lease is not None:
        out = ["Spinoff lease: %s" % lease["state"], "  %s" % t(lease["reason"], 120),
               "  instance %s  generation %d  sequence %d" % (t(lease["instance_id"], 64), lease["generation"],
                                                             lease["seq"]),
               "  valid %s .. %s" % (t(lease["not_before"]), t(lease["not_after"])),
               "  key %s" % t(lease["key_fingerprint"], 60), "  clock %s (high-water %s)" % (
                   t(lease["clock"]), t(lease["clock_high_water"]))]
        return out
    if fg is None:
        return ["Forge " + (unavailable(data["forge"]) or "")]
    out = ["   %-20s %-11s %-11s %-8s %4s  %s" % ("instance", "platform", "profile", "status", "gen", "lease until")]
    for d in fg["deployments"]:
        lease_doc = d.get("lease") or {}
        out.append("   %-20s %-11s %-11s %-8s %4s  %s" % (t(d["instance_id"], 20), t(d["platform"], 11),
                                                         t(d["profile"], 11), t(d["status"], 8),
                                                         lease_doc.get("generation", ""),
                                                         lease_doc.get("not_after") or "-"))
    return out


def reports(data: Data, selected: int = 0, detail: Optional[Dict[str, Any]] = None, **_: Any) -> List[str]:
    rp = result(data, "reports")
    if rp is None:
        return ["Reports " + (unavailable(data["reports"]) or "")]
    out = ["   %-24s %-21s %-20s %-16s %s" % ("report", "kind", "created", "result", "subject")]
    for i, r in enumerate(rp["reports"]):
        subj = r.get("subject") or {}
        label = subj.get("kname") or subj.get("name") or short(subj.get("sha256"))
        out.append("%s %-24s %-21s %-20s %-16s %s" % (">" if i == selected else " ", t(r["report_id"], 24),
                                                      t(r.get("kind"), 21), t(r.get("created"), 20),
                                                      t(r.get("result"), 16), t(label, 40)))
    if detail:
        rep = detail["report"]
        out += ["", "%s  %s  ledger %s  signatures %d" % (t(rep["kind"]), t(rep["result"]),
                                                         {True: "matches", False: "DIFFERS", None: "n/a"}[
                                                             detail.get("ledger_match")], len(detail["signatures"]))]
        out += ["  " + t(line, 400) for line in rep["statement"]]
        for f in (rep["body"].get("findings") or [])[:12]:
            out.append("  %-8s %-32s %s" % (t(f.get("severity"), 8), t(f.get("code"), 32), t(f.get("detail"), 120)))
    return out


def audit(data: Data, page: Optional[Dict[str, Any]] = None, message: str = "", **_: Any) -> List[str]:
    au = result(data, "audit")
    if au is None:
        return ["Audit " + (unavailable(data["audit"]) or "")]
    out = ["Ledger head: entry %d, hash %s" % (au["head_seq"], short(au["head"], 32))]
    entries = ((page or {}).get("result") or {}).get("entries", [])
    for rec in entries:
        e = rec["entry"]
        fields = e.get("fields") or {}
        summary = " ".join("%s=%s" % (t(k, 20), t(v, 40)) for k, v in sorted(fields.items())
                           if k not in ("signature",))
        out.append("%6d %s %-22s %s" % (e["seq"], t(e["time"], 20), t(e["event"], 22), summary))
    return out


def watchdog(data: Data, **_: Any) -> List[str]:
    wd = result(data, "watchdog")
    if wd is None:
        return ["Watchdog " + (unavailable(data["watchdog"]) or "")]
    out = ["Adapter: %s (%s)" % (t(wd["adapter"]), "enabled" if wd["enabled"] else "disabled"),
           "Paused: %s" % (", ".join(wd["paused"]) or "nothing")]
    if wd["paused"]:
        out.append("Reason: %s  since %s" % (t(wd["reason"], 200), wd["since"]))
    out.append("Recent signals:")
    for s in wd["recent"][-12:]:
        out.append("  %s %-15s %-8s %s" % (s["time"], t(s["kind"], 15), t(s["severity"], 8), t(s["detail"], 120)))
    return out


RENDER: Dict[str, Callable[..., List[str]]] = {
    "dashboard": dashboard, "devices": devices, "keys": keys, "vault": vault, "airlock": airlock, "forge": forge,
    "reports": reports, "audit": audit, "watchdog": watchdog}


def render(screen: str, data: Data, *, width: int, height: int, message: str = "", **state: Any) -> List[str]:
    """The whole screen: tabs, body, key help, message line. Exactly ``height`` lines of at most ``width``."""
    try:
        body = RENDER[screen](data, **state)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        body = ["This screen could not be displayed (unexpected data: %s)." % type(exc).__name__]
    lines = [tabs(screen), "-" * width] + body
    footer = ["-" * width, "keys: 1-9 screens  q quit  r refresh  " + KEYS[screen], t(message, 400)]
    room = max(height - len(footer), 0)
    lines = lines[:room] + [""] * (room - len(lines[:room])) + footer
    return [line[:width] if line.isprintable() and line.isascii() else t(line, width)[:width]
            for line in lines[:height]]
