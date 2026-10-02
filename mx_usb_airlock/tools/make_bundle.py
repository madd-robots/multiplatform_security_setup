#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the release bundle in dist/:

  mx_usb_airlock-<version>.tar.gz                  the archive
  mx_usb_airlock-<version>.tar.gz.sha256           ARCHIVE SHA-256 (check before extracting)
  mx_usb_airlock-<version>.SHA256SUMS.sha256       BUNDLE DIGEST: SHA-256 of the SHA256SUMS file inside
                                                   the archive; this is the value install.sh --expect-digest takes

The archive is deterministic (sorted entries, fixed timestamps, root ownership,
gzip header without a timestamp): the same sources built with the same
Python/zlib give a byte-identical file, so a published bundle can be checked
by rebuilding it from the git source.

Usage: python3 -I -B tools/make_bundle.py [OUTPUT_DIR]
"""

import gzip
import hashlib
import io
import os
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
# Fixed timestamp (2026-01-01T00:00:00Z) unless SOURCE_DATE_EPOCH is set.
MTIME = int(os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))
EXECUTABLE = {"install.sh", "termux/usb_airlock_prepare.py"}


def payload_sources():
    sources = {}
    for name in ("airlock.py", "config.example.json", "README.md", "SECURITY_MODEL.md", "RECOVERY.md",
                 "TESTING.md", "install.sh", "tests/test_airlock.py", "tests/test_install.py",
                 "tests/test_integration_destructive.py", "tests/test_v11.py", "termux/usb_airlock_prepare.py"):
        sources[name] = ROOT / name
    sources["LICENSE"] = REPO / "LICENSE"
    return sources


def read_version():
    match = re.search(r'^APP_VERSION = "([0-9A-Za-z.+-]+)"$', (ROOT / "airlock.py").read_text(), re.M)
    if not match:
        raise SystemExit("cannot find APP_VERSION in airlock.py")
    return match.group(1)


def check_installer(version, names):
    text = (ROOT / "install.sh").read_text()
    m_version = re.search(r"^VERSION=([0-9A-Za-z.+-]+)$", text, re.M)
    m_payload = re.search(r'^PAYLOAD="([^"]*)"$', text, re.M)
    if not m_version or m_version.group(1) != version:
        raise SystemExit("install.sh VERSION does not match airlock.py APP_VERSION %s" % version)
    if not m_payload or sorted(m_payload.group(1).split()) != sorted(names):
        raise SystemExit("install.sh PAYLOAD does not match the bundle file list")


def read_file(path):
    if path.is_symlink() or not path.is_file():
        raise SystemExit("refusing non-regular payload file: %s" % path)
    data = path.read_bytes()
    if path.suffix in (".py", ".sh") and b"\x60" in data:
        raise SystemExit("payload file contains a backtick: %s" % path)
    return data


def tar_entry(name, size, mode, is_dir=False):
    info = tarfile.TarInfo(name)
    info.size = 0 if is_dir else size
    info.mtime = MTIME
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return info


def build(out_dir, quiet=False):
    version = read_version()
    sources = payload_sources()
    check_installer(version, list(sources))
    files = {name: read_file(path) for name, path in sources.items()}
    sums = "".join("%s  %s\n" % (hashlib.sha256(files[n]).hexdigest(), n) for n in sorted(files)).encode("ascii")
    files["SHA256SUMS"] = sums
    top = "mx_usb_airlock-%s" % version

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for directory in (top, top + "/termux", top + "/tests"):
            tar.addfile(tar_entry(directory, 0, 0o755, is_dir=True))
        for name in sorted(files):
            data = files[name]
            mode = 0o755 if name in EXECUTABLE else 0o644
            tar.addfile(tar_entry("%s/%s" % (top, name), len(data), mode), io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())

    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / ("%s.tar.gz" % top)
    archive.write_bytes(compressed.getvalue())
    archive_sha = hashlib.sha256(compressed.getvalue()).hexdigest()
    (out_dir / (archive.name + ".sha256")).write_text("%s  %s\n" % (archive_sha, archive.name))
    digest = hashlib.sha256(sums).hexdigest()
    # sha256sum format, checkable after extraction: sha256sum -c <this file>
    (out_dir / ("%s.SHA256SUMS.sha256" % top)).write_text("%s  %s/SHA256SUMS\n" % (digest, top))
    if not quiet:
        print("archive        : %s" % archive)
        print("archive SHA-256              : %s  (%s.sha256)" % (archive_sha, archive.name))
        print("bundle digest (--expect-digest): %s  (%s.SHA256SUMS.sha256)" % (digest, top))
    return archive, archive_sha, digest


if __name__ == "__main__":
    build(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "dist")
