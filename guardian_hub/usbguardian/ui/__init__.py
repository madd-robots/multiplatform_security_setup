# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 9: terminal UI (curses, standard library only).

The UI is one more broker client. It holds no authority of its own: every
action is a broker operation, authorized, audited and, where the broker
requires it, confirmed with a YubiKey touch exactly as on the command line.
It opens no network port and never asks for or shows a secret.

model    fetch broker data per screen; an unavailable section becomes a message
views    pure functions: data -> lines of printable ASCII (device strings escaped)
actions  owner and destructive actions (assurance, erase, cancel, sign, checkpoint, resume)
app      the curses loop: keys, refresh, prompts
"""
