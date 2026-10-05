# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 3 device engine (Linux).

scanner   read-only collection from sysfs and mountinfo (runs in a worker)
identity  canonical device identity and fingerprint, change detection
assess    findings that decide whether Guardian will use a device (D4)
surface   destructive full-surface write/read-back and capacity proof (D4)
"""
