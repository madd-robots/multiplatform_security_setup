# SPDX-License-Identifier: GPL-3.0-or-later
"""Storage structure inspection: partition table, partitions, boot structures.

Runs in a sandboxed worker on a read-only descriptor of the whole device.
Every value read here comes from the device and is hostile: offsets and
counts are bounded before use, nothing is repaired, and anything that does
not add up is reported rather than interpreted.

Findings use the device-engine severities (INFO, REVIEW, BLOCKING).
"""

from __future__ import annotations

import os
import struct
import uuid
import zlib
from typing import Any, Callable, Dict, List, Optional

SEV_INFO, SEV_REVIEW, SEV_BLOCKING = "INFO", "REVIEW", "BLOCKING"
MAX_GPT_ENTRIES = 256
MAX_PARTITIONS = 16
SECTOR = 512

ESP_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
GPT_TYPES = {
    ESP_GUID: "efi_system",
    "21686148-6449-6e6f-744e-656564454649": "bios_boot",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "basic_data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "linux_data",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "microsoft_reserved",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "windows_recovery",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "linux_swap",
}
MBR_DATA_TYPES = {0x01: "fat12", 0x04: "fat16", 0x06: "fat16", 0x07: "ntfs_exfat", 0x0B: "fat32", 0x0C: "fat32",
                  0x0E: "fat16", 0x83: "linux"}
MBR_BOOT_TYPES = {0xEF: "efi_system", 0xEE: "gpt_protective"}
EXTENDED = (0x05, 0x0F, 0x85)
# Filesystems the airlock mounts (read-only) for acquisition.
SUPPORTED_FILESYSTEMS = ("vfat", "exfat", "ntfs", "ext2", "ext3", "ext4")

ReadAt = Callable[[int, int], bytes]


def _finding(code: str, severity: str, detail: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def detect_filesystem(boot: bytes) -> Optional[str]:
    """Filesystem type from the first 4 KiB of a volume (signatures only)."""
    if len(boot) >= 11 and boot[3:11] == b"EXFAT   ":
        return "exfat"
    if len(boot) >= 11 and boot[3:11] == b"NTFS    ":
        return "ntfs"
    if len(boot) >= 1082 and boot[1080:1082] == b"\x53\xef":
        compat, incompat = struct.unpack_from("<II", boot, 1024 + 0x5C)
        if incompat & 0x40 or incompat & 0x80:  # extents or 64bit
            return "ext4"
        return "ext3" if compat & 0x4 else "ext2"
    if len(boot) >= 512 and boot[510:512] == b"\x55\xaa":
        if boot[82:90] == b"FAT32   " or boot[54:62] in (b"FAT16   ", b"FAT12   ", b"FAT     "):
            return "vfat"
    if len(boot) >= 0x8006 and boot[0x8001:0x8006] == b"CD001":
        return "iso9660"
    return None


def _boot_code_present(sector0: bytes) -> bool:
    """MBR bootstrap area (first 440 bytes) holds code rather than zeros."""
    return any(sector0[:440])


def _gpt(read_at: ReadAt, size: int, lbs: int) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    header = read_at(lbs, lbs)
    if header[:8] != b"EFI PART":
        return {"ok": False, "findings": [_finding("GPT_HEADER_MISSING", SEV_BLOCKING,
                                                   "protective MBR but no GPT header")], "partitions": []}
    hsize = struct.unpack_from("<I", header, 12)[0]
    if not 92 <= hsize <= lbs:
        return {"ok": False, "findings": [_finding("GPT_HEADER_INVALID", SEV_BLOCKING, "bad header size")],
                "partitions": []}
    stored_crc = struct.unpack_from("<I", header, 16)[0]
    check = bytearray(header[:hsize])
    check[16:20] = b"\x00\x00\x00\x00"
    if zlib.crc32(bytes(check)) & 0xFFFFFFFF != stored_crc:
        findings.append(_finding("GPT_HEADER_CRC", SEV_BLOCKING, "GPT header checksum mismatch"))
    first_usable, last_usable = struct.unpack_from("<QQ", header, 40)
    entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", header, 72)
    if count > MAX_GPT_ENTRIES or entry_size < 128 or entry_size > 1024 or entry_size % 8:
        return {"ok": False, "findings": findings + [_finding("GPT_ENTRIES_INVALID", SEV_BLOCKING,
                                                              "entry count or size out of range")], "partitions": []}
    total_sectors = size // lbs
    if not 2 <= entries_lba < total_sectors or last_usable >= total_sectors or first_usable > last_usable:
        return {"ok": False, "findings": findings + [_finding("GPT_LAYOUT_INVALID", SEV_BLOCKING,
                                                              "GPT points outside the device")], "partitions": []}
    raw = read_at(entries_lba * lbs, count * entry_size)
    if zlib.crc32(raw) & 0xFFFFFFFF != entries_crc:
        findings.append(_finding("GPT_ENTRIES_CRC", SEV_BLOCKING, "GPT partition entry checksum mismatch"))
    parts = []
    for i in range(count):
        entry = raw[i * entry_size:(i + 1) * entry_size]
        if len(entry) < 128 or not any(entry[:16]):
            continue
        type_guid = str(uuid.UUID(bytes_le=entry[:16]))
        first, last, attrs = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        kind = GPT_TYPES.get(type_guid, "unknown")
        if first < first_usable or last > last_usable or first > last:
            findings.append(_finding("PARTITION_OUT_OF_RANGE", SEV_BLOCKING,
                                     "GPT partition %d lies outside the usable area" % (i + 1)))
        parts.append({"index": i + 1, "start": first * lbs, "length": (last - first + 1) * lbs if last >= first else 0,
                      "type": kind, "type_id": type_guid, "bootable": bool(attrs & 0x4), "name": name[:36]})
    return {"ok": True, "findings": findings, "partitions": parts}


def inspect_structure(read_at: ReadAt, size: int, logical_block_size: int = SECTOR) -> Dict[str, Any]:
    """Describe the device layout.  ``read_at(offset, length)`` returns up to ``length`` bytes."""
    lbs = logical_block_size if logical_block_size in (512, 4096) else SECTOR
    findings: List[Dict[str, str]] = []
    sector0 = read_at(0, 4096)
    scheme = "none"
    partitions: List[Dict[str, Any]] = []
    whole_fs = detect_filesystem(read_at(0, 0x8800))
    if len(sector0) >= 512 and sector0[510:512] == b"\x55\xaa" and whole_fs is None:
        entries = [sector0[446 + 16 * i:462 + 16 * i] for i in range(4)]
        types = [e[4] for e in entries]
        if 0xEE in types:
            scheme = "gpt"
            if any(t not in (0, 0xEE) for t in types):
                findings.append(_finding("HYBRID_MBR", SEV_BLOCKING, "GPT disk also carries MBR partitions"))
            gpt = _gpt(read_at, size, lbs)
            findings += gpt["findings"]
            partitions = gpt["partitions"]
        else:
            scheme = "mbr"
            for i, e in enumerate(entries):
                ptype = e[4]
                if ptype == 0:
                    continue
                start, count = struct.unpack_from("<II", e, 8)
                if e[0] not in (0, 0x80):
                    findings.append(_finding("MBR_ENTRY_INVALID", SEV_BLOCKING, "invalid boot indicator"))
                if ptype in EXTENDED:
                    findings.append(_finding("EXTENDED_PARTITION", SEV_REVIEW, "logical partitions are not inspected"))
                kind = MBR_DATA_TYPES.get(ptype) or MBR_BOOT_TYPES.get(ptype) or "unknown"
                partitions.append({"index": i + 1, "start": start * SECTOR, "length": count * SECTOR, "type": kind,
                                   "type_id": "0x%02x" % ptype, "bootable": e[0] == 0x80, "name": ""})
    elif whole_fs is not None:
        scheme = "superfloppy"  # a filesystem directly on the device, no partition table
    else:
        findings.append(_finding("NO_PARTITION_TABLE", SEV_REVIEW, "no partition table or known filesystem"))

    if scheme in ("mbr", "superfloppy") and len(sector0) >= 440 and _boot_code_present(sector0) \
            and whole_fs is None:
        findings.append(_finding("MBR_BOOT_CODE", SEV_REVIEW, "boot code present in the master boot record"))
    if len(partitions) > MAX_PARTITIONS:
        findings.append(_finding("TOO_MANY_PARTITIONS", SEV_BLOCKING, "%d partitions" % len(partitions)))
        partitions = partitions[:MAX_PARTITIONS]
    spans = sorted((p["start"], p["start"] + p["length"], p["index"]) for p in partitions)
    for (s1, e1, i1), (s2, e2, i2) in zip(spans, spans[1:]):
        if s2 < e1:
            findings.append(_finding("PARTITIONS_OVERLAP", SEV_BLOCKING, "partitions %d and %d overlap" % (i1, i2)))
    for p in partitions:
        if p["length"] <= 0 or p["start"] + p["length"] > size:
            findings.append(_finding("PARTITION_OUT_OF_RANGE", SEV_BLOCKING,
                                     "partition %d lies outside the device" % p["index"]))
            p["filesystem"] = None
            continue
        p["filesystem"] = detect_filesystem(read_at(p["start"], 0x8800))
        if p["type"] == "efi_system":
            findings.append(_finding("EFI_SYSTEM_PARTITION", SEV_REVIEW,
                                     "partition %d is an EFI System Partition (boot structure)" % p["index"]))
        if p["bootable"]:
            findings.append(_finding("BOOT_FLAG", SEV_REVIEW, "partition %d is marked bootable" % p["index"]))
        if p["type"] in ("bios_boot", "windows_recovery", "unknown", "gpt_protective"):
            findings.append(_finding("UNEXPECTED_PARTITION", SEV_REVIEW,
                                     "partition %d has type %s" % (p["index"], p["type_id"])))
        if p["filesystem"] is not None and p["filesystem"] not in SUPPORTED_FILESYSTEMS:
            findings.append(_finding("UNSUPPORTED_FILESYSTEM", SEV_REVIEW,
                                     "partition %d holds %s" % (p["index"], p["filesystem"])))
    if whole_fs == "iso9660" or any(p.get("filesystem") == "iso9660" for p in partitions):
        findings.append(_finding("BOOTABLE_IMAGE_LAYOUT", SEV_REVIEW, "ISO 9660 image layout (installer media?)"))
    if scheme != "superfloppy" and len([p for p in partitions if p.get("filesystem") in SUPPORTED_FILESYSTEMS]) > 1:
        findings.append(_finding("MULTIPLE_DATA_PARTITIONS", SEV_REVIEW, "more than one data partition"))
    return {"scheme": scheme, "whole_filesystem": whole_fs, "partitions": partitions, "findings": findings}


def fd_reader(fd: int, size: int) -> ReadAt:
    def read_at(offset: int, length: int) -> bytes:
        if offset < 0 or offset >= size:
            return b""
        return os.pread(fd, min(length, size - offset, 1024 * 1024), offset)
    return read_at
