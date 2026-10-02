#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""usb_airlock_prepare: trusted-side packager for mx_usb_airlock V1.1 (Android Termux).

Builds a signed, encrypted transfer package from an explicit directory or an
explicit file list:

    AIRLOCK_TRANSFER/
      TRANSFER_ID           transfer identifier (also inside the signed manifest)
      manifest.json         authoritative manifest: every file's path, size, SHA-256, type
      manifest.minisig      minisign (Ed25519) signature over manifest.json
      payload.age           age (X25519) encryption of a deterministic ustar container
      README_TRANSFER.txt   plain-text description, never executed

Keys:
  * the minisign SECRET signing key stays in the Termux key directory (default
    ~/.usb_airlock); only its PUBLIC key and fingerprint go to the MX machine;
  * the age RECIPIENT (public) comes from the MX machine (init-transport-key);
    the matching identity never leaves MX, so ciphertext and decryption secret
    are never on the transport USB together.

Nothing is downloaded, nothing is executed from the input files, and no shell
is used: external tools run as fixed argument arrays.

Requires (Termux): pkg install python minisign age   (no upgrade needed)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

APP = "usb_airlock_prepare"
VERSION = "1.1.0"
TRANSFER_FORMAT = "mx_usb_airlock.transfer"
TRANSFER_FORMAT_VERSION = 1
ENCRYPTION_ALGORITHM = "age-x25519-v1"
SIGNATURE_ALGORITHM = "minisign-ed25519"
CONTAINER_FORMAT = "ustar"
PACKAGE_DIR = "AIRLOCK_TRANSFER"
TAR_MTIME = 1767225600  # fixed: the container is deterministic for identical inputs

# Same defaults as the MX side (airlock.py DEFAULT_CONFIG) so a package that is
# accepted here is not refused there.
DEFAULT_ALLOWED_EXTENSIONS = ("ps1", "txt", "md", "json", "sha256", "sha256sum", "csv")
FILE_TYPES = {"ps1": "powershell-script", "txt": "text", "md": "markdown", "json": "json", "csv": "csv",
              "sha256": "checksum-list", "sha256sum": "checksum-list"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 200
MAX_DEPTH = 6
MAX_NAME_LENGTH = 128
SYSTEM_METADATA_FILES = frozenset({"autorun.inf", "desktop.ini", "thumbs.db", "ehthumbs.db", "iconcache.db",
                                   ".ds_store"})
WINDOWS_RESERVED = frozenset(["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
                             + ["COM%d" % i for i in range(10)] + ["LPT%d" % i for i in range(10)])
WINDOWS_INVALID = frozenset('<>:"|?*\\/')
BIDI_AND_INVISIBLE = frozenset({0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067,
                                0x2068, 0x2069, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD})
AGE_RECIPIENT_RE = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")
TRANSFER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
SAFE_ENV = {"LC_ALL": "C", "LANG": "C"}

KEY_SECRET = "signing.key"
KEY_PUBLIC = "signing.pub"
RECIPIENT_FILE = "mx_recipient.txt"

README_TEXT = """MX USB AIRLOCK TRANSFER PACKAGE (format 1)

This directory was produced by usb_airlock_prepare on a trusted device.
It contains no programs and nothing in it is meant to be opened or run.

  manifest.json     list of the files inside the encrypted payload, with SHA-256
  manifest.minisig  Ed25519 signature over manifest.json
  payload.age       encrypted container (age), decryptable only by the
                    intended MX airlock machine
  TRANSFER_ID       identifier of this transfer

On the MX airlock: insert ONLY this USB and run "mx-usb-airlock ingest".
"""


class PrepareError(Exception):
    """Refusal with an operator-facing reason; nothing is written on refusal."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def say(text: str) -> None:
    print(text, flush=True)


def shown(value: Any, limit: int = 160) -> str:
    out = []
    for ch in str(value):
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o <= 0xFF:
            out.append("\\x%02x" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    text = "".join(out)
    return text if len(text) <= limit else text[:limit] + "...(truncated)"


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_transfer_id() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_fingerprint(hex_digest: str) -> str:
    h = hex_digest.upper()
    return "-".join(h[i:i + 4] for i in range(0, len(h), 4))


def tool_dirs() -> List[str]:
    dirs = []
    prefix = os.environ.get("PREFIX", "")
    if prefix and os.path.isabs(prefix):
        dirs.append(os.path.join(prefix, "bin"))
    dirs += ["/data/data/com.termux/files/usr/bin", "/usr/bin", "/bin", "/usr/local/bin"]
    return dirs


def find_tool(name: str) -> str:
    """Resolve a tool from fixed directories (never PATH); owner must be you or root, not group/world-writable."""
    for directory in tool_dirs():
        path = os.path.join(directory, name)
        try:
            st = os.stat(path)
            dst = os.stat(directory)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022 or dst.st_mode & 0o022:
            continue
        return path
    raise PrepareError("required tool '%s' not found (Termux: pkg install %s)" % (name, "age" if name.startswith("age") else name))


def run_tool(name: str, args: Sequence[str], data: Optional[bytes] = None, interactive: bool = False,
             timeout: int = 600) -> subprocess.CompletedProcess:
    argv = [find_tool(name)] + [str(a) for a in args]
    env = dict(SAFE_ENV)
    env["PATH"] = os.pathsep.join(tool_dirs())
    if os.environ.get("HOME"):
        env["HOME"] = os.environ["HOME"]
    if interactive:
        # inherits the terminal so minisign can ask for the key password
        return subprocess.run(argv, env=env, timeout=timeout, shell=False, check=False)
    return subprocess.run(argv, input=data, capture_output=True, env=env, timeout=timeout, shell=False, check=False)


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path: Path) -> None:
    os.makedirs(str(path), 0o700, exist_ok=True)
    st = os.lstat(str(path))
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise PrepareError("%s is not a private directory owned by you" % path)
    os.chmod(str(path), 0o700)


def parse_public_key(raw: bytes) -> Dict[str, str]:
    lines = [l.strip() for l in raw.decode("ascii", "replace").splitlines() if l.strip()]
    b64 = lines[-1] if lines else ""
    try:
        blob = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error):
        raise PrepareError("invalid minisign public key")
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise PrepareError("invalid minisign public key")
    return {"key_id": blob[2:10][::-1].hex().upper(), "fingerprint": hashlib.sha256(blob[10:]).hexdigest(), "b64": b64}


# ---------------------------------------------------------------------------
# input validation (filenames are untrusted data)
# ---------------------------------------------------------------------------

def name_problems(name: str, allow_non_ascii: bool = False) -> List[str]:
    problems = []
    if name in ("", ".", ".."):
        return ["traversal or empty name"]
    for ch in name:
        o = ord(ch)
        if o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:
            problems.append("control character")
        elif o in BIDI_AND_INVISIBLE or unicodedata.category(ch) in ("Cf", "Co", "Cn", "Cs", "Zl", "Zp"):
            problems.append("invisible/bidi/unassigned character")
        elif ch in WINDOWS_INVALID:
            problems.append("character not allowed on Windows (%s)" % shown(ch))
    if not name.isascii() and not allow_non_ascii:
        problems.append("non-ASCII name (lookalike defence; the MX airlock refuses it by default)")
    if name.isascii() is False and unicodedata.normalize("NFC", name) != name:
        problems.append("not NFC-normalised")
    if name[-1] in " .":
        problems.append("trailing space or dot")
    if name[0] == " ":
        problems.append("leading space")
    if name.split(".", 1)[0].rstrip(" ").upper() in WINDOWS_RESERVED:
        problems.append("Windows reserved device name")
    if len(name) > MAX_NAME_LENGTH or len(name.encode("utf-8", "replace")) > 255:
        problems.append("name too long")
    return sorted(set(problems))


def extension(name: str) -> str:
    stripped = name.lstrip(".")
    return stripped.rsplit(".", 1)[1].lower() if "." in stripped else ""


def file_problems(rel: str, allowed: Sequence[str]) -> List[str]:
    parts = rel.split("/")
    problems = []
    for part in parts:
        problems += ["%s: %s" % (shown(part), p) for p in name_problems(part)]
    name = parts[-1]
    if name.startswith(".") or name.lower() in SYSTEM_METADATA_FILES:
        problems.append("hidden or system metadata file")
    if extension(name) not in allowed:
        problems.append("file type .%s is not on the allowlist (%s)" % (shown(extension(name)), ", ".join(allowed)))
    if len(parts) > MAX_DEPTH + 1:
        problems.append("nested too deeply")
    return problems


def overlaps(a: str, b: str) -> bool:
    return a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep)


BROAD_LOCATIONS = ("/", "/sdcard", "/storage", "/storage/emulated", "/storage/emulated/0", "/data",
                   "/data/data/com.termux/files", "/data/data/com.termux/files/usr")


def refuse_broad_location(path: Path) -> None:
    home = os.path.realpath(os.path.expanduser("~"))
    real = os.path.realpath(str(path))
    if real in BROAD_LOCATIONS or real == home or real == os.path.join(home, "storage") \
            or real == os.path.join(home, "storage", "shared"):
        raise PrepareError("%s is a broad location; point --source-dir at a dedicated folder holding only the "
                           "approved files" % real)


def collect_inputs(source_dir: Optional[str], file_list: Optional[List[str]], base: Optional[str],
                   keys_dir: Path, allowed: Sequence[str]) -> Tuple[Path, List[str]]:
    """Return (canonical root, sorted relative paths). Nothing outside the root is ever selected."""
    if bool(source_dir) == bool(file_list):
        raise PrepareError("give exactly one of --source-dir DIR or --files FILE...")
    if source_dir:
        root = Path(os.path.realpath(source_dir))
        refuse_broad_location(root)
        if not root.is_dir():
            raise PrepareError("--source-dir is not a directory")
        rels: List[str] = []

        def walk(directory: Path, prefix: str, depth: int) -> None:
            with os.scandir(str(directory)) as it:
                entries = sorted(it, key=lambda e: e.name)
            for entry in entries:
                rel = (prefix + "/" + entry.name) if prefix else entry.name
                st = os.lstat(entry.path)
                if stat.S_ISDIR(st.st_mode):
                    if depth >= MAX_DEPTH:
                        raise PrepareError("%s is nested too deeply" % shown(rel))
                    walk(Path(entry.path), rel, depth + 1)
                else:
                    rels.append(rel)
                if len(rels) > MAX_FILES:
                    raise PrepareError("more than %d files" % MAX_FILES)

        walk(root, "", 0)
    else:
        root = Path(os.path.realpath(base)) if base else None
        rels = []
        for item in file_list or []:
            absolute = os.path.abspath(item)
            if os.path.islink(absolute):
                raise PrepareError("%s is a symbolic link (refused)" % shown(item))
            if root is None:
                rel = os.path.basename(absolute)
                file_root = Path(os.path.realpath(os.path.dirname(absolute)))
                if rels and file_root != root_guess:
                    raise PrepareError("files come from different directories; give --base DIR")
                root_guess = file_root
            else:
                real = os.path.realpath(absolute)
                if os.path.commonpath([real, str(root)]) != str(root) or real == str(root):
                    raise PrepareError("%s lies outside --base" % shown(item))
                rel = os.path.relpath(real, str(root)).replace(os.sep, "/")
            rels.append(rel)
        if root is None:
            root = root_guess
    if not rels:
        raise PrepareError("no files selected")
    if overlaps(os.path.realpath(str(keys_dir)), str(root)):
        raise PrepareError("the source location overlaps the key directory; keys must never be packaged")
    if len(rels) != len(set(rels)):
        raise PrepareError("duplicate logical path in the file list")
    folded: Dict[str, str] = {}
    files_and_dirs = set()
    for rel in rels:
        parts = rel.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            key = unicodedata.normalize("NFC", prefix).casefold()
            if folded.setdefault(key, prefix) != prefix:
                raise PrepareError("%s collides with %s on case-insensitive filesystems" % (shown(prefix), shown(folded[key])))
            if i < len(parts):
                files_and_dirs.add(prefix)
    if files_and_dirs & set(rels):
        raise PrepareError("a path is both a file and a directory")
    problems = []
    for rel in rels:
        if rel.startswith("/") or ".." in rel.split("/") or "\x00" in rel:
            problems.append("%s: traversal or absolute path" % shown(rel))
            continue
        problems += ["%s: %s" % (shown(rel), p) for p in file_problems(rel, allowed)]
    if problems:
        raise PrepareError("input refused:\n  " + "\n  ".join(problems[:40]))
    return root, sorted(rels)


def read_input(root: Path, rel: str) -> bytes:
    """Open each component without following links; accept only single-link regular files under root."""
    fds = [os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    try:
        parts = rel.split("/")
        for part in parts[:-1]:
            try:
                fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1]))
            except OSError:
                raise PrepareError("%s: a directory on the path is a link or not a directory" % shown(rel))
        st = os.stat(parts[-1], dir_fd=fds[-1], follow_symlinks=False)
        kind = ("symbolic link" if stat.S_ISLNK(st.st_mode) else "FIFO" if stat.S_ISFIFO(st.st_mode) else
                "socket" if stat.S_ISSOCK(st.st_mode) else "device node" if stat.S_ISCHR(st.st_mode) or
                stat.S_ISBLK(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode) else None)
        if kind:
            raise PrepareError("%s is a %s (only regular files are packaged)" % (shown(rel), kind))
        if st.st_nlink != 1:
            raise PrepareError("%s has %d hard links (refused: unexpected hard-link behaviour)" % (shown(rel), st.st_nlink))
        if st.st_size > MAX_FILE_BYTES:
            raise PrepareError("%s is larger than %d bytes" % (shown(rel), MAX_FILE_BYTES))
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fds[-1])
        try:
            fst = os.fstat(fd)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode):
                raise PrepareError("%s changed while being opened" % shown(rel))
            chunks, remaining = [], MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        for fd in reversed(fds):
            os.close(fd)
    if len(data) != st.st_size or len(data) > MAX_FILE_BYTES:
        raise PrepareError("%s changed size while being read" % shown(rel))
    if not data.startswith((b"\xff\xfe", b"\xfe\xff")) and b"\x00" in data:
        raise PrepareError("%s contains NUL bytes; it is not a text file (the MX airlock would refuse it)" % shown(rel))
    return data


# ---------------------------------------------------------------------------
# package building
# ---------------------------------------------------------------------------

def build_container(contents: Dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for rel in sorted(contents):
            info = tarfile.TarInfo(rel)
            info.size = len(contents[rel])
            info.mtime = TAR_MTIME
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.type = tarfile.REGTYPE
            try:
                tar.addfile(info, io.BytesIO(contents[rel]))
            except ValueError:
                raise PrepareError("%s does not fit the ustar container (path too long)" % shown(rel))
    return raw.getvalue()


def build_manifest(transfer_id: str, created_utc: str, contents: Dict[str, bytes], payload: bytes) -> bytes:
    files = [{"relative_path": rel, "size": len(data), "sha256": sha256_hex(data),
              "file_type": FILE_TYPES.get(extension(rel), "text")} for rel, data in sorted(contents.items())]
    manifest = {
        "format": TRANSFER_FORMAT,
        "format_version": TRANSFER_FORMAT_VERSION,
        "transfer_id": transfer_id,
        "created_utc": created_utc,
        "file_count": len(files),
        "total_plaintext_bytes": sum(f["size"] for f in files),
        "encryption_algorithm": ENCRYPTION_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "container_format": CONTAINER_FORMAT,
        "payload": {"filename": "payload.age", "size": len(payload), "sha256": sha256_hex(payload)},
        "files": files,
    }
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def signed_comment(transfer_id: str, manifest_sha256: str) -> str:
    return "mx_usb_airlock transfer_id=%s manifest_sha256=%s" % (transfer_id, manifest_sha256)


def prepare(keys_dir: Path, output: Path, source_dir: Optional[str] = None, files: Optional[List[str]] = None,
            base: Optional[str] = None, transfer_id: Optional[str] = None, created_utc: Optional[str] = None,
            interactive_sign: bool = True) -> Path:
    secret = keys_dir / KEY_SECRET
    if not secret.is_file() or not (keys_dir / KEY_PUBLIC).is_file():
        raise PrepareError("no signing key; run: %s init-keys" % APP)
    if not (keys_dir / RECIPIENT_FILE).is_file():
        raise PrepareError("no MX recipient; run: %s set-recipient age1..." % APP)
    recipient = (keys_dir / RECIPIENT_FILE).read_text().strip()
    if not AGE_RECIPIENT_RE.match(recipient):
        raise PrepareError("stored MX recipient is invalid")
    transfer_id = transfer_id or new_transfer_id()
    if not TRANSFER_ID_RE.match(transfer_id):
        raise PrepareError("invalid transfer id")
    created_utc = created_utc or utc_now()
    out_real = os.path.realpath(str(output))
    keys_real = os.path.realpath(str(keys_dir))
    if overlaps(out_real, keys_real):
        raise PrepareError("the output directory overlaps the key directory")
    final = Path(out_real) / PACKAGE_DIR
    if os.path.lexists(str(final)):
        raise PrepareError("%s already exists; refusing to overwrite" % final)

    root, rels = collect_inputs(source_dir, files, base, keys_dir, DEFAULT_ALLOWED_EXTENSIONS)
    contents = {rel: read_input(root, rel) for rel in rels}
    total = sum(len(v) for v in contents.values())
    if total > MAX_TOTAL_BYTES:
        raise PrepareError("total size %d exceeds %d bytes" % (total, MAX_TOTAL_BYTES))

    container = build_container(contents)
    enc = run_tool("age", ["-r", recipient], data=container)
    if enc.returncode != 0 or not enc.stdout:
        raise PrepareError("age encryption failed: %s" % shown(enc.stderr.decode("utf-8", "replace").strip()))
    payload = enc.stdout
    container = b""
    manifest = build_manifest(transfer_id, created_utc, contents, payload)

    os.makedirs(out_real, 0o700, exist_ok=True)
    stage = Path(out_real) / (".%s.%s.tmp" % (PACKAGE_DIR, secrets.token_hex(4)))
    os.mkdir(str(stage), 0o700)
    try:
        write_private(stage / "manifest.json", manifest)
        write_private(stage / "payload.age", payload)
        write_private(stage / "TRANSFER_ID", (transfer_id + "\n").encode("ascii"))
        write_private(stage / "README_TRANSFER.txt", README_TEXT.encode("ascii"))
        sign = run_tool("minisign", ["-S", "-s", str(secret), "-m", str(stage / "manifest.json"),
                                     "-x", str(stage / "manifest.minisig"),
                                     "-t", signed_comment(transfer_id, sha256_hex(manifest))],
                        interactive=interactive_sign)
        if sign.returncode != 0 or not (stage / "manifest.minisig").is_file():
            raise PrepareError("signing failed (wrong key password?)")
        assert_no_secret_material(stage, secret, contents)
        os.rename(str(stage), str(final))
    except BaseException:
        for child in stage.iterdir() if stage.exists() else []:
            child.unlink()
        if stage.exists():
            stage.rmdir()
        raise
    return final


def assert_no_secret_material(package: Path, secret: Path, contents: Dict[str, bytes]) -> None:
    """Self-check before publishing: no signing-key material and no plaintext payload file in the package."""
    secret_raw = secret.read_bytes()
    secret_lines = [l.strip() for l in secret_raw.splitlines() if l.strip() and not l.startswith(b"untrusted comment")]
    allowed = {"manifest.json", "manifest.minisig", "payload.age", "TRANSFER_ID", "README_TRANSFER.txt"}
    for child in package.iterdir():
        if child.name not in allowed or child.is_symlink() or not child.is_file():
            raise PrepareError("unexpected entry %s in package" % shown(child.name))
        data = child.read_bytes()
        if any(line and line in data for line in secret_lines):
            raise PrepareError("signing key material detected in %s; package NOT written" % child.name)
        if child.name == "payload.age":
            if not data.startswith(b"age-encryption.org/v1\n"):
                raise PrepareError("payload is not age ciphertext")
            for body in contents.values():
                if len(body) >= 32 and body in data:
                    raise PrepareError("plaintext detected in payload; package NOT written")


# ---------------------------------------------------------------------------
# verification (self-check of a finished package, without decrypting)
# ---------------------------------------------------------------------------

def verify_package(keys_dir: Path, package: Path) -> Dict[str, Any]:
    pub = keys_dir / KEY_PUBLIC
    res = run_tool("minisign", ["-V", "-Q", "-p", str(pub), "-m", str(package / "manifest.json"),
                                "-x", str(package / "manifest.minisig")])
    if res.returncode != 0:
        raise PrepareError("signature verification FAILED")
    manifest_raw = (package / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    if res.stdout.decode("utf-8", "replace").strip() != signed_comment(manifest["transfer_id"], sha256_hex(manifest_raw)):
        raise PrepareError("trusted comment does not bind this manifest")
    payload = (package / "payload.age").read_bytes()
    if sha256_hex(payload) != manifest["payload"]["sha256"] or len(payload) != manifest["payload"]["size"]:
        raise PrepareError("payload does not match the signed manifest")
    marker = (package / "TRANSFER_ID").read_text().strip()
    if marker != manifest["transfer_id"]:
        raise PrepareError("TRANSFER_ID does not match the signed manifest")
    return manifest


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_init_keys(args: argparse.Namespace) -> int:
    keys = Path(args.keys_dir)
    private_dir(keys)
    if os.path.lexists(str(keys / KEY_SECRET)) or os.path.lexists(str(keys / KEY_PUBLIC)):
        raise PrepareError("a signing key already exists in %s; it is never overwritten (a key change is a "
                           "security-sensitive event: move the old key away deliberately first)" % keys)
    extra = ["-W"] if args.no_password else []
    if args.no_password:
        say("WARNING: the signing key will NOT be password-protected.")
    res = run_tool("minisign", ["-G", "-p", str(keys / KEY_PUBLIC), "-s", str(keys / KEY_SECRET)] + extra,
                   interactive=not args.no_password)
    if res.returncode != 0:
        raise PrepareError("key generation failed")
    os.chmod(str(keys / KEY_SECRET), 0o600)
    os.chmod(str(keys / KEY_PUBLIC), 0o644)
    return cmd_show_keys(args)


def cmd_set_recipient(args: argparse.Namespace) -> int:
    keys = Path(args.keys_dir)
    private_dir(keys)
    recipient = args.recipient.strip()
    if not AGE_RECIPIENT_RE.match(recipient):
        raise PrepareError("not an age X25519 recipient (expected age1...)")
    path = keys / RECIPIENT_FILE
    if os.path.lexists(str(path)):
        current = path.read_text().strip()
        if current == recipient:
            say("This MX recipient is already set.")
            return 0
        if not args.replace:
            raise PrepareError("a different MX recipient is set (%s); use --replace deliberately" % current)
        os.rename(str(path), str(keys / ("retired-%s-%s" % (secrets.token_hex(3), RECIPIENT_FILE))))
    write_private(path, (recipient + "\n").encode("ascii"))
    say("MX transport recipient set: %s" % recipient)
    return 0


def cmd_show_keys(args: argparse.Namespace) -> int:
    keys = Path(args.keys_dir)
    pub = keys / KEY_PUBLIC
    if pub.is_file():
        key = parse_public_key(pub.read_bytes())
        say("Signing PUBLIC key file : %s" % pub)
        say("Key ID                  : %s" % key["key_id"])
        say("SHA-256 fingerprint     : %s" % format_fingerprint(key["fingerprint"]))
        say("Public key (base64)     : %s" % key["b64"])
        say("On MX: mx-usb-airlock trust-signing-key --public-key-string %s" % key["b64"])
        say("       and type the first five fingerprint groups: %s" % format_fingerprint(key["fingerprint"])[:24])
    else:
        say("No signing key yet (run init-keys).")
    rec = keys / RECIPIENT_FILE
    say("MX transport recipient  : %s" % (rec.read_text().strip() if rec.is_file() else "(not set; run set-recipient)"))
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    package = prepare(Path(args.keys_dir), Path(args.output), source_dir=args.source_dir, files=args.files,
                      base=args.base)
    manifest = verify_package(Path(args.keys_dir), package)
    key = parse_public_key((Path(args.keys_dir) / KEY_PUBLIC).read_bytes())
    say("PACKAGE CREATED AND SELF-VERIFIED: %s" % package)
    say("  transfer id   : %s" % manifest["transfer_id"])
    say("  files         : %d (%d bytes)" % (manifest["file_count"], manifest["total_plaintext_bytes"]))
    say("  payload sha256: %s" % manifest["payload"]["sha256"])
    say("  signing key   : %s  fingerprint %s" % (key["key_id"], format_fingerprint(key["fingerprint"])))
    say("Copy the whole %s directory to the root of the transport USB (for example with the Android files app" % PACKAGE_DIR)
    say("or: cp -r %s ~/storage/<usb>/). Copy nothing else onto that USB." % shown(str(package)))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = verify_package(Path(args.keys_dir), Path(args.package))
    say("PACKAGE SIGNATURE AND PAYLOAD HASH VERIFIED: transfer %s, %d files" % (manifest["transfer_id"], manifest["file_count"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP, description="Prepare a signed, encrypted mx_usb_airlock transfer package.")
    parser.add_argument("--version", action="version", version="%s %s" % (APP, VERSION))
    parser.add_argument("--keys-dir", default=os.path.join(os.path.expanduser("~"), ".usb_airlock"),
                        help="private key directory on this trusted device (default ~/.usb_airlock)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init-keys", help="create the signing key pair once (never overwrites)")
    p.add_argument("--no-password", action="store_true", help="do not password-protect the signing key (not recommended)")
    p = sub.add_parser("set-recipient", help="store the MX machine's age recipient (from init-transport-key)")
    p.add_argument("recipient")
    p.add_argument("--replace", action="store_true")
    sub.add_parser("show-keys", help="show key ID, fingerprint and recipient")
    p = sub.add_parser("prepare", help="build AIRLOCK_TRANSFER/ in --output")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source-dir", help="dedicated folder holding ONLY the approved files")
    group.add_argument("--files", nargs="+", help="explicit list of approved files")
    p.add_argument("--base", help="with --files: directory the relative paths are computed from")
    p.add_argument("--output", required=True, help="directory in which AIRLOCK_TRANSFER/ is created")
    p = sub.add_parser("verify", help="re-check a finished package's signature and payload hash")
    p.add_argument("package")
    return parser


COMMANDS = {"init-keys": cmd_init_keys, "set-recipient": cmd_set_recipient, "show-keys": cmd_show_keys,
            "prepare": cmd_prepare, "verify": cmd_verify}


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except PrepareError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("ERROR: %s" % shown(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
