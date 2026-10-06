# SPDX-License-Identifier: GPL-3.0-or-later
"""Machine identity binding for a spinoff lease.

The binding is a domain-separated digest of identifiers the machine
exposes: the firmware (DMI) product UUID and serial numbers, and the OS
machine-id. Raw values never leave the machine; only the digest and the
names of the sources used do.

Limits, stated plainly: root on the machine can read and fake these
values, and a cloned disk carries the same machine-id. The binding stops a
lease meant for one machine from being applied to another by mistake or by
casual copying; it is not hardware attestation. The spinoff key, generated
on the machine and never exported, is the stronger binding. A changed
source (new mainboard, regenerated machine-id) changes the binding and
needs a reissue by the owner.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

from ..common.canonical import canonical_digest
from ..common.errors import ConfigError

DOMAIN = "guardian/machine-id/v1"
SOURCES: Tuple[Tuple[str, str], ...] = (
    ("dmi_product_uuid", "sys/class/dmi/id/product_uuid"),
    ("dmi_product_serial", "sys/class/dmi/id/product_serial"),
    ("dmi_board_serial", "sys/class/dmi/id/board_serial"),
    ("os_machine_id", "etc/machine-id"),
)
# Placeholder values firmware vendors ship; they identify nothing.
_JUNK = re.compile(r"^(0+|f+|none|null|n/a|na|default string|to be filled by o\.e\.m\.|system serial number|"
                   r"not specified|not applicable|0123456789|[0-]+|[f-]+)$", re.IGNORECASE)


def _read(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        data = os.read(fd, 257)
    except OSError:
        return ""
    finally:
        os.close(fd)
    if len(data) > 256:
        return ""
    text = data.decode("ascii", "replace").strip()
    if not text or _JUNK.match(text) or not text.isprintable():
        return ""
    return text.lower()


def machine_identity(root: Path = Path("/")) -> Tuple[str, List[str]]:
    """Return (binding digest hex, names of the sources used)."""
    values: Dict[str, str] = {}
    for name, rel in SOURCES:
        value = _read(Path(root) / rel)
        if value:
            values[name] = value
    if not values:
        raise ConfigError("no machine identifier is readable (DMI or machine-id); cannot bind a lease",
                          code="MACHINE_ID_UNAVAILABLE")
    return canonical_digest(DOMAIN, values).hex(), sorted(values)
