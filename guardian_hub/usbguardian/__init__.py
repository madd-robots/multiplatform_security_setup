# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian USB Encryption Hub.

Implemented so far (see ROADMAP.md):
  Stage 1  usbguardian.common   errors, canonical serialization, safe names,
                                private file I/O, structured logging
  Stage 2  usbguardian.runtime  broker, isolated workers, IPC, authorization
"""

APP_NAME = "usbguardian"
APP_VERSION = "0.2.0"
