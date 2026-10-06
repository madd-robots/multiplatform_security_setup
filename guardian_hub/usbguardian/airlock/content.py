# SPDX-License-Identifier: GPL-3.0-or-later
"""Static content inspection of one quarantined file. Nothing is executed.

Runs in a sandboxed worker on a read-only descriptor. The file name is
data (only its extension is used, to report a mismatch); the content
alone decides the type. Archives are listed, never extracted.

Type detection, text decoding, the text heuristics and the PowerShell
review patterns are ported from ``mx_usb_airlock`` (same repository).

Severities: INFO, REVIEW, BLOCKING. Codes in STRUCTURAL make the state
STRUCTURAL ANOMALY. ``TYPE_POLICY`` says which detected types can pass,
need review, are blocked in normal data-transfer mode (executables, disk
and boot images: those need a distinct workflow) or are unsupported.
"""

from __future__ import annotations

import io
import lzma
import math
import os
import re
import stat
import tarfile
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple

SEV_INFO, SEV_REVIEW, SEV_BLOCKING = "INFO", "REVIEW", "BLOCKING"
HEAD_BYTES = 64 * 1024
MAX_TEXT_REVIEW = 16 * 1024 * 1024
MAX_PDF_SCAN = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
MAX_ARCHIVE_EXPANDED = 4 * 1024 ** 3
BOMB_RATIO = 200
BOMB_MIN_SIZE = 10 * 1024 * 1024

TYPE_POLICY = {
    "empty": "review", "text": "pass", "json": "pass", "csv": "pass",
    "script_shell": "review", "script_powershell": "review", "script_other": "review",
    "image_png": "pass", "image_jpeg": "pass", "image_gif": "pass",
    "pdf": "review", "office_ooxml": "review", "office_ole": "review", "zip": "review", "tar": "review",
    "compressed": "unsupported", "archive_7z": "unsupported", "archive_rar": "unsupported",
    "executable_elf": "blocked", "executable_pe": "blocked", "executable_mz": "blocked",
    "executable_macho": "blocked", "java_class": "blocked",
    "disk_image": "blocked", "unknown_binary": "unsupported",
}
STRUCTURAL = frozenset({
    "ARCHIVE_PATH_TRAVERSAL", "ARCHIVE_LINK_ESCAPE", "ARCHIVE_SPECIAL_FILE", "ARCHIVE_TOO_MANY_MEMBERS",
    "ARCHIVE_TOO_LARGE", "ARCHIVE_BOMB_SUSPECTED", "ARCHIVE_OVERLAPPING_ENTRIES", "ARCHIVE_CORRUPT",
    "TYPE_DETECTION_FAILED",
})
EXPECTED_BY_EXTENSION = {
    "txt": ("text", "json", "csv", "empty"), "md": ("text", "empty"), "log": ("text", "empty"),
    "json": ("json", "text"), "csv": ("csv", "text"), "sh": ("script_shell", "text"),
    "bash": ("script_shell", "text"), "ps1": ("script_powershell", "text"),
    "png": ("image_png",), "jpg": ("image_jpeg",), "jpeg": ("image_jpeg",), "gif": ("image_gif",),
    "pdf": ("pdf",), "zip": ("zip",), "tar": ("tar",), "docx": ("office_ooxml",), "xlsx": ("office_ooxml",),
    "pptx": ("office_ooxml",), "doc": ("office_ole",), "xls": ("office_ole",), "ppt": ("office_ole",),
    "gz": ("compressed", "tar"), "tgz": ("tar",), "xz": ("compressed", "tar"), "bz2": ("compressed", "tar"),
    "7z": ("archive_7z",), "rar": ("archive_rar",), "exe": ("executable_pe", "executable_mz"),
    "iso": ("disk_image",), "img": ("disk_image",),
}
ARCHIVE_EXTENSIONS = frozenset({"zip", "tar", "gz", "tgz", "xz", "bz2", "7z", "rar", "cab", "iso", "img", "jar",
                                "apk", "deb", "rpm", "zst", "lz4", "lzma", "wim", "dmg", "vhd", "vhdx"})
EXECUTABLE_EXTENSIONS = frozenset({"exe", "dll", "msi", "scr", "com", "bat", "cmd", "ps1", "psm1", "vbs", "js",
                                   "jse", "wsf", "hta", "lnk", "sh", "bash", "py", "pl", "rb", "elf", "so", "bin",
                                   "run", "appimage", "deb", "rpm", "jar", "apk", "efi", "ko"})

Finding = Dict[str, Any]


def finding(code: str, severity: str, detail: str, lines: Optional[List[int]] = None) -> Finding:
    out: Finding = {"code": code, "severity": severity, "detail": detail}
    if lines:
        out["lines"] = lines[:20]
    return out


def extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[1].lower()[:16] if "." in base.strip(".") else ""


# -- type detection ---------------------------------------------------------------------------------

def detect_type(head: bytes, size: int, tail: bytes) -> str:
    if size == 0:
        return "empty"
    if head[:4] == b"\x7fELF":
        return "executable_elf"
    if head[:2] == b"MZ":
        if len(head) >= 0x40:
            off = int.from_bytes(head[0x3C:0x40], "little")
            if 0 < off <= len(head) - 4 and head[off:off + 4] == b"PE\x00\x00":
                return "executable_pe"
        return "executable_mz"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "executable_macho"
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "java_class" if len(head) > 7 and head[7] >= 45 else "executable_macho"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image_png"
    if head[:3] == b"\xff\xd8\xff":
        return "image_jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image_gif"
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "office_ole"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or (head[:3] == b"BZh" and head[4:10] == b"1AY&SY"):
        return "compressed"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive_7z"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "archive_rar"
    if head[:4] == b"QFI\xfb" or head[:4] == b"KDMV" or (len(tail) >= 512 and tail[-512:-504] == b"conectix") \
            or head[:8] == b"vhdxfile":
        return "disk_image"
    if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "disk_image"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and head[:3] in (b"\xeb\x3c\x90", b"\xeb\x58\x90", b"\xeb\x52\x90"):
        return "disk_image"  # a boot sector or filesystem image
    return "text_candidate"


# -- text -------------------------------------------------------------------------------------------

BIDI_CONTROLS = frozenset({0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                           0x2066, 0x2067, 0x2068, 0x2069})
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD})
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{64,}")


def decode_text(data: bytes) -> Tuple[Optional[str], List[Finding]]:
    """Decode for inspection only (bytes are exported unchanged).  None means not text."""
    flags: List[Finding] = []
    if data.startswith((b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
        return None, flags
    if data.startswith(b"\xef\xbb\xbf"):
        encoding, body = "utf-8", data[3:]
    elif data.startswith(b"\xff\xfe"):
        encoding, body = "utf-16-le", data[2:]
    elif data.startswith(b"\xfe\xff"):
        encoding, body = "utf-16-be", data[2:]
    else:
        encoding, body = "utf-8", data
    if encoding == "utf-8" and b"\x00" in body:
        return None, flags
    try:
        text = body.decode(encoding)
    except UnicodeDecodeError:
        if encoding != "utf-8":
            return None, flags
        try:
            text = body.decode("cp1252")
        except UnicodeDecodeError:
            return None, flags
        flags.append(finding("LEGACY_8BIT_ENCODING", SEV_REVIEW, "not valid UTF-8; inspected as Windows-1252"))
    if "\x00" in text:
        return None, flags
    controls = sum(1 for ch in text if (ord(ch) < 0x20 and ch not in "\t\n\r\x0c") or 0x7F <= ord(ch) <= 0x9F)
    if controls:
        if controls > max(8, len(text) // 100):
            return None, flags
        flags.append(finding("CONTROL_CHARACTERS", SEV_REVIEW, "%d non-printing control characters" % controls))
    return text, flags


def _entropy(token: str) -> float:
    counts: Dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(token))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def text_heuristics(text: str) -> List[Finding]:
    bidi, zw, long_lines, b64, entropy = [], [], [], [], []
    non_ascii = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.isascii():
            for ch in line:
                o = ord(ch)
                if o > 0x7F:
                    non_ascii += 1
                if o in BIDI_CONTROLS and (not bidi or bidi[-1] != number):
                    bidi.append(number)
                elif o in ZERO_WIDTH and not (o == 0xFEFF and number == 1 and line.startswith(ch)):
                    if not zw or zw[-1] != number:
                        zw.append(number)
        if len(line) > 1000:
            long_lines.append(number)
        if BASE64_BLOB_RE.search(line):
            b64.append(number)
        for match in TOKEN_RE.finditer(line):
            if _entropy(match.group(0)) > 4.8:
                entropy.append(number)
                break
    out = []
    if bidi:
        out.append(finding("UNICODE_BIDI_CONTROL", SEV_REVIEW, "bidirectional controls: text may display "
                                                              "differently from how it runs", bidi))
    if zw:
        out.append(finding("INVISIBLE_CHARACTER", SEV_REVIEW, "zero-width or invisible characters", zw))
    if long_lines:
        out.append(finding("EXTREMELY_LONG_LINE", SEV_REVIEW, "lines longer than 1000 characters", long_lines))
    if b64:
        out.append(finding("BASE64_BLOB", SEV_REVIEW, "long base64-like data", b64))
    if entropy:
        out.append(finding("HIGH_ENTROPY_DATA", SEV_REVIEW, "high-entropy token (packed or encrypted data?)", entropy))
    if non_ascii:
        out.append(finding("NON_ASCII_CHARACTERS", SEV_INFO, "%d non-ASCII characters (lookalikes?)" % non_ascii))
    return out


# -- static script review ---------------------------------------------------------------------------

BACKTICK = chr(0x60)  # built from its code point: Guardian's own sources contain no backtick
_SH = (
    ("EVAL", r"(?<![\w.-])eval\b(?!-)", "eval"),
    ("EXEC", r"(?<![\w.-])exec\b(?!-)", "exec"),
    ("SHELL_DASH_C", r"(?<![\w.-])(?:ba|da|z|k|c)?sh\s+(?:-[a-z]*\s+)*-[a-z]*c\b", "sh -c / bash -c"),
    ("LEGACY_BACKTICK", re.escape(BACKTICK) + r"[^" + re.escape(BACKTICK) + r"\n]*" + re.escape(BACKTICK),
     "legacy backtick command substitution"),
    ("COMMAND_SUBSTITUTION", r"\$\(", "command substitution"),
    ("DOWNLOAD_PIPED_TO_SHELL", r"(?:curl|wget|fetch)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b",
     "download piped into a shell"),
    ("NETWORK_DOWNLOAD", r"(?<![\w.-])(?:curl|wget|fetch)(?![\w-])", "network download tool"),
    ("RAW_BLOCK_WRITE", r"\bof=/dev/|>\s*/dev/(?:sd|nvme|mmcblk|hd|vd|xvd|loop|disk)", "raw block device write"),
    ("DD", r"(?<![\w.-])dd\s+[a-z]+=", "dd"),
    ("FILESYSTEM_TOOL", r"(?<![\w.-])(?:mkfs(?:\.\w+)?|fdisk|sfdisk|parted|sgdisk|gdisk|wipefs|mkswap|blkdiscard)"
     r"(?![\w-])", "partition or filesystem tool"),
    ("BLOCK_DEVICE_PATH", r"/dev/(?:sd[a-z]|nvme\d|mmcblk\d|hd[a-z]|vd[a-z]|xvd[a-z])", "block device path"),
    ("BOOT_FIRMWARE", r"efibootmgr|efivarfs|/sys/firmware/efi|grub2?-install|update-grub|bootctl|/boot/efi",
     "boot or EFI configuration"),
    ("FIRMWARE_FLASH", r"flashrom|fwupdmgr|fwupdtool", "firmware update tool"),
    ("MODULE_LOADING", r"(?<![\w.-])(?:insmod|modprobe|rmmod|kexec)(?![\w-])", "kernel module loading or kexec"),
    ("UDEV_PERSISTENCE", r"/etc/udev/|/lib/udev/rules\.d|udevadm\s+(?:control|trigger)", "udev rules"),
    ("CRON_PERSISTENCE", r"crontab|/etc/cron|/var/spool/cron|(?<![\w-])at\s+now", "cron or at jobs"),
    ("BOOT_PERSISTENCE", r"/etc/rc\.local|/etc/init\.d/|update-rc\.d|/etc/rc\d\.d|systemctl\s+enable|/etc/systemd/"
     r"|\.bashrc|\.bash_profile|/etc/profile", "boot or login persistence"),
    ("PRIVILEGE_ESCALATION", r"(?<![\w.-])(?:sudo|su|pkexec|doas)(?![\w-])|/etc/sudoers|chmod\s+[ugo]*\+s"
     r"|chmod\s+[0-7]?[4-7][0-7]{3}\b", "privilege escalation or setuid"),
    ("CAPABILITY_CHANGE", r"(?<![\w.-])(?:setcap|capsh)(?![\w-])", "file capability changes"),
    ("MOUNT_OPERATION", r"(?<![\w.-])(?:mount|umount|losetup)(?![\w-])", "mount operations"),
    ("NAMESPACE_CHROOT", r"(?<![\w.-])(?:unshare|nsenter|chroot|pivot_root)(?![\w-])", "namespaces or chroot"),
    ("DESTRUCTIVE_REMOVAL", r"rm\s+-[a-zA-Z]*[rRf][a-zA-Z]*\s+(?:/|~|\$HOME|\*|\"/)|--no-preserve-root|(?<![\w.-])shred\s",
     "destructive removal"),
    ("PACKAGE_REPOSITORY", r"/etc/apt/sources\.list|apt-key|add-apt-repository|/etc/apt/trusted\.gpg|dpkg\s+-i"
     r"|--allow-unauthenticated", "package repository changes"),
    ("ENCODED_PAYLOAD", r"base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|(?:\\x[0-9a-fA-F]{2}){8,}",
     "encoded payload decoding"),
    ("INLINE_INTERPRETER", r"(?:python[23]?|perl|ruby|node|php)\s+-[a-zA-Z]*[ce]\b", "inline interpreter code"),
    ("NETWORK_SHELL", r"/dev/tcp/|/dev/udp/|(?<![\w.-])nc\s[^\n]*-[a-z]*e\b|(?<![\w.-])socat(?![\w-])",
     "network shell"),
    ("HISTORY_TAMPERING", r"history\s+-c|HISTFILE=|unset\s+HISTFILE", "shell history tampering"),
)
SH_PATTERNS = tuple((c, re.compile(rx), d) for c, rx, d in _SH)

_PS = (
    ("ENCODED_COMMAND", r"(?<![\w-])-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+['\"]?[A-Za-z0-9+/]{16,}"
     r"={0,2}", "encoded PowerShell command"),
    ("FROMBASE64STRING", r"FromBase64String", "base64 decoding"),
    ("INVOKE_EXPRESSION", r"\bInvoke-Expression\b|(?<![\w-])iex(?![\w-])", "dynamic code execution"),
    ("DOWNLOAD", r"\.Download(?:String|File|Data)(?:Async|TaskAsync)?\s*\(|\b(?:Invoke-WebRequest|Invoke-RestMethod"
     r"|Start-BitsTransfer)\b|(?<![\w-])(?:iwr|irm|curl|wget|bitsadmin)(?![\w-])|Net\.WebClient", "download"),
    ("REFLECTION_LOADING", r"Reflection\.Assembly|Assembly\]::Load|GetDelegateForFunctionPointer|VirtualAlloc",
     "reflection-based loading"),
    ("ADD_TYPE", r"\bAdd-Type\b", "inline compiled code"),
    ("LOLBIN", r"\b(?:rundll32|regsvr32|mshta|certutil)\b", "living-off-the-land binary"),
    ("PERSISTENCE", r"\b(?:Register-ScheduledTask|New-ScheduledTask\w*|schtasks|New-Service)\b"
     r"|CurrentVersion\\+Run|__EventFilter|CommandLineEventConsumer", "persistence"),
    ("REMOTING", r"\b(?:Enter-PSSession|New-PSSession|Enable-PSRemoting)\b|\bwinrm\b", "remoting"),
    ("DEFENDER_OR_FIREWALL", r"\bSet-MpPreference\b|\bAdd-MpPreference\b|Set-NetFirewallProfile|netsh\s+(?:adv)?firewall",
     "security setting change"),
    ("EXECUTION_POLICY", r"Set-ExecutionPolicy|(?<![\w-])-(?:ExecutionPolicy|ep|exec)\s+(?:Bypass|Unrestricted)\b",
     "execution policy weakening"),
    ("HIDDEN_WINDOW", r"(?<![\w-])-(?:WindowStyle|w|win|window)\s+(?:Hidden|h)\b", "hidden window"),
    ("DISK_OR_BOOT", r"\b(?:Clear-Disk|Initialize-Disk|Format-Volume|New-Partition|bcdedit|bcdboot|diskpart)\b",
     "disk or boot configuration"),
)
PS_PATTERNS = tuple((c, re.compile(rx, re.IGNORECASE), d) for c, rx, d in _PS)
PS_ESCAPE_IN_WORD = re.compile("[A-Za-z]" + re.escape(BACKTICK) + "[A-Za-z]")


def scan_lines(text: str, patterns: Any, *, strip_char: Optional[str] = None) -> List[Finding]:
    hits: Dict[str, List[int]] = {}
    desc = {c: d for c, _rx, d in patterns}
    for number, line in enumerate(text.splitlines(), 1):
        variants = [line]
        if strip_char and strip_char in line:
            variants.append(line.replace(strip_char, ""))
            if PS_ESCAPE_IN_WORD.search(line):
                hits.setdefault("ESCAPE_CHARACTER_OBFUSCATION", []).append(number)
                desc["ESCAPE_CHARACTER_OBFUSCATION"] = "escape character inside a word (keyword splitting)"
        for code, rx, _d in patterns:
            if any(rx.search(v) for v in variants):
                hits.setdefault(code, []).append(number)
    return [finding(code, SEV_REVIEW, desc[code], lines) for code, lines in hits.items()]


def classify_text(text: str, ext: str) -> str:
    first = text.lstrip("\ufeff").split("\n", 1)[0]
    if first.startswith("#!"):
        if re.search(r"\b(?:ba|da|z|k|c)?sh\b", first):
            return "script_shell"
        if "pwsh" in first or "powershell" in first.lower():
            return "script_powershell"
        return "script_other"
    if ext in ("sh", "bash", "zsh", "ksh", "command"):
        return "script_shell"
    if ext in ("ps1", "psm1", "psd1"):
        return "script_powershell"
    if ext in ("py", "pl", "rb", "js", "vbs", "lua", "php", "bat", "cmd"):
        return "script_other"
    if ext == "json":
        return "json"
    if ext == "csv":
        return "csv"
    return "text"


# -- archives ---------------------------------------------------------------------------------------

def _member_name_findings(name: str) -> List[Finding]:
    out = []
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or ".." in norm.split("/") or "\x00" in name:
        out.append(finding("ARCHIVE_PATH_TRAVERSAL", SEV_BLOCKING, "member %r escapes the archive root" % name[:80]))
    ext = extension(norm)
    if ext in ARCHIVE_EXTENSIONS:
        out.append(finding("NESTED_ARCHIVE", SEV_REVIEW, "nested archive %r is not inspected" % name[:80]))
    if ext in EXECUTABLE_EXTENSIONS:
        out.append(finding("EXECUTABLE_MEMBER", SEV_REVIEW, "member %r looks executable" % name[:80]))
    return out


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f["code"], f)
    return list(seen.values())


def inspect_zip(fobj: Any) -> Tuple[List[Finding], Dict[str, Any]]:
    out: List[Finding] = []
    try:
        zf = zipfile.ZipFile(fobj)
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError, NotImplementedError):
        return [finding("ARCHIVE_CORRUPT", SEV_BLOCKING, "zip directory unreadable")], {}
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        return [finding("ARCHIVE_TOO_MANY_MEMBERS", SEV_BLOCKING, "%d members" % len(infos))], {}
    total = 0
    spans = []
    names = set()
    for info in infos:
        total += info.file_size
        out += _member_name_findings(info.filename)
        if info.filename in names:
            out.append(finding("DUPLICATE_MEMBER", SEV_REVIEW, "member %r appears twice" % info.filename[:80]))
        names.add(info.filename)
        if info.file_size > BOMB_MIN_SIZE and info.file_size > BOMB_RATIO * max(info.compress_size, 1):
            out.append(finding("ARCHIVE_BOMB_SUSPECTED", SEV_BLOCKING,
                               "member %r expands %d-fold" % (info.filename[:80],
                                                             info.file_size // max(info.compress_size, 1))))
        if info.flag_bits & 0x1:
            out.append(finding("ENCRYPTED_MEMBER", SEV_REVIEW, "encrypted member cannot be inspected"))
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            out.append(finding("ARCHIVE_SYMLINK", SEV_REVIEW, "member %r is a symlink" % info.filename[:80]))
        spans.append((info.header_offset, info.header_offset + 30 + len(info.filename.encode("utf-8", "replace"))
                       + info.compress_size))
    spans.sort()
    for (s1, e1), (s2, _e2) in zip(spans, spans[1:]):
        if s2 < e1:
            out.append(finding("ARCHIVE_OVERLAPPING_ENTRIES", SEV_BLOCKING, "zip entries overlap (zip bomb pattern)"))
            break
    if total > MAX_ARCHIVE_EXPANDED:
        out.append(finding("ARCHIVE_TOO_LARGE", SEV_BLOCKING, "expands to %d bytes" % total))
    office = "[Content_Types].xml" in names
    if office and any(n.lower().endswith("vbaproject.bin") for n in names):
        out.append(finding("OFFICE_MACROS", SEV_REVIEW, "document contains VBA macros"))
    return _dedupe(out), {"members": len(infos), "expanded_bytes": total, "office": office}


def inspect_tar(fobj: Any) -> Tuple[List[Finding], Dict[str, Any]]:
    out: List[Finding] = []
    count = total = 0
    try:
        with tarfile.open(fileobj=fobj, mode="r:*") as tf:
            while True:
                member = tf.next()
                if member is None:
                    break
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    out.append(finding("ARCHIVE_TOO_MANY_MEMBERS", SEV_BLOCKING, "more than %d members"
                                       % MAX_ARCHIVE_MEMBERS))
                    break
                total += max(member.size, 0)
                if total > MAX_ARCHIVE_EXPANDED:
                    out.append(finding("ARCHIVE_TOO_LARGE", SEV_BLOCKING, "expands beyond %d bytes"
                                       % MAX_ARCHIVE_EXPANDED))
                    break
                out += _member_name_findings(member.name)
                if member.issym() or member.islnk():
                    target = member.linkname.replace("\\", "/")
                    if target.startswith("/") or ".." in target.split("/"):
                        out.append(finding("ARCHIVE_LINK_ESCAPE", SEV_BLOCKING,
                                           "link %r points outside the archive" % member.name[:80]))
                    else:
                        out.append(finding("ARCHIVE_SYMLINK", SEV_REVIEW, "member %r is a link" % member.name[:80]))
                elif member.isdev() or member.isfifo():
                    out.append(finding("ARCHIVE_SPECIAL_FILE", SEV_BLOCKING,
                                       "member %r is a device or FIFO" % member.name[:80]))
                if member.mode & (stat.S_ISUID | stat.S_ISGID):
                    out.append(finding("SETUID_MEMBER", SEV_REVIEW, "member %r is setuid/setgid" % member.name[:80]))
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError):
        out.append(finding("ARCHIVE_CORRUPT", SEV_BLOCKING, "tar stream unreadable"))
    return _dedupe(out), {"members": count, "expanded_bytes": total}


def _pdf_findings(data: bytes) -> List[Finding]:
    out = []
    for token, code in ((b"/JavaScript", "PDF_JAVASCRIPT"), (b"/JS", "PDF_JAVASCRIPT"),
                        (b"/OpenAction", "PDF_AUTO_ACTION"), (b"/AA", "PDF_AUTO_ACTION"),
                        (b"/Launch", "PDF_LAUNCH"), (b"/EmbeddedFile", "PDF_EMBEDDED_FILE"),
                        (b"/RichMedia", "PDF_RICH_MEDIA"), (b"/XFA", "PDF_XFA_FORM")):
        if token in data and code not in [f["code"] for f in out]:
            out.append(finding(code, SEV_REVIEW, "PDF contains %s" % token.decode()))
    return out


# -- entry point ------------------------------------------------------------------------------------

def inspect_file(fd: int, name: str) -> Dict[str, Any]:
    """Inspect the file behind ``fd`` (read-only, regular).  Returns {type, findings, details}."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        return {"type": "unknown_binary", "findings": [finding("TYPE_DETECTION_FAILED", SEV_BLOCKING,
                                                               "not a regular file")], "details": {}}
    size = st.st_size
    head = os.pread(fd, max(HEAD_BYTES, 0x8800), 0)
    tail = os.pread(fd, 512, max(size - 512, 0)) if size >= 512 else b""
    ext = extension(name)
    kind = detect_type(head, size, tail)
    findings: List[Finding] = []
    details: Dict[str, Any] = {}
    if kind == "text_candidate":
        if size > MAX_TEXT_REVIEW:
            kind = "unknown_binary"
            findings.append(finding("TOO_LARGE_FOR_TEXT_REVIEW", SEV_REVIEW, "text larger than %d bytes is not "
                                                                            "reviewed" % MAX_TEXT_REVIEW))
        else:
            data = os.pread(fd, size, 0)
            text, flags = decode_text(data)
            if text is None:
                kind = "unknown_binary"
            else:
                kind = classify_text(text, ext)
                findings += flags + text_heuristics(text)
                if kind == "script_shell":
                    findings += scan_lines(text, SH_PATTERNS)
                elif kind == "script_powershell":
                    findings += scan_lines(text, PS_PATTERNS, strip_char=BACKTICK)
                elif kind == "script_other":
                    findings.append(finding("SCRIPT_NOT_REVIEWED", SEV_REVIEW, "script language without static "
                                                                              "review rules"))
                elif kind == "csv" and re.search(r"(?m)(?:^|,)\s*[\"']?[=+@]", text):
                    findings.append(finding("CSV_FORMULA", SEV_REVIEW, "cells that may run as spreadsheet formulas"))
    elif kind in ("zip", "tar", "compressed"):
        fobj = io.BufferedReader(_FdRaw(fd, size))
        if kind == "zip":
            f2, details = inspect_zip(fobj)
            if details.get("office"):
                kind = "office_ooxml"
        else:
            f2, details = inspect_tar(fobj)
            if kind == "compressed" and not any(f["code"] == "ARCHIVE_CORRUPT" for f in f2):
                kind = "tar"
            elif kind == "compressed":
                f2 = []  # a compressed single file, not a tar stream: unsupported, not corrupt
        findings += f2
    elif kind == "pdf":
        findings += _pdf_findings(os.pread(fd, min(size, MAX_PDF_SCAN), 0))
    elif kind == "office_ole":
        data = os.pread(fd, min(size, MAX_PDF_SCAN), 0)
        if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data:
            findings.append(finding("OFFICE_MACROS", SEV_REVIEW, "document contains VBA macros"))
    expected = EXPECTED_BY_EXTENSION.get(ext)
    if expected is not None and kind not in expected:
        findings.append(finding("EXTENSION_MISMATCH", SEV_REVIEW, "extension .%s but content is %s" % (ext, kind)))
    elif expected is None and ext in EXECUTABLE_EXTENSIONS and TYPE_POLICY.get(kind) == "pass":
        findings.append(finding("EXECUTABLE_EXTENSION", SEV_REVIEW, "extension .%s is executable on some systems" % ext))
    return {"type": kind, "findings": _dedupe(findings), "details": details}


class _FdRaw(io.RawIOBase):
    """Seekable read-only view of a descriptor using pread (the fd offset is never moved)."""

    def __init__(self, fd: int, size: int):
        self.fd, self.size, self.pos = fd, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self.pos, 2: self.size}[whence]
        self.pos = max(0, base + offset)
        return self.pos

    def tell(self) -> int:
        return self.pos

    def readinto(self, buf: Any) -> int:
        data = os.pread(self.fd, len(buf), self.pos)
        buf[:len(data)] = data
        self.pos += len(data)
        return len(data)


def item_state(kind: str, findings: List[Finding], scanner: Optional[Dict[str, Any]]) -> str:
    """Guardian policy: inspection results -> state.  Only PASS and REVIEW_REQUIRED can be approved."""
    if scanner is None or scanner.get("status") in ("unavailable", "error"):
        return "BLOCKED"  # scanner failure fails closed
    if scanner.get("status") == "found":
        return "MALWARE_DETECTED_BY_SCANNER"
    codes = {f["code"] for f in findings}
    if codes & STRUCTURAL:
        return "STRUCTURAL_ANOMALY"
    policy = TYPE_POLICY.get(kind, "unsupported")
    if policy == "unsupported":
        return "UNSUPPORTED_FILE_TYPE"
    if policy == "blocked" or any(f["severity"] == SEV_BLOCKING for f in findings):
        return "BLOCKED"
    if policy == "review" or any(f["severity"] == SEV_REVIEW for f in findings):
        return "REVIEW_REQUIRED"
    return "PASS"
