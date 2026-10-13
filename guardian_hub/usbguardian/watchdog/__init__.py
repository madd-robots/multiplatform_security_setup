# SPDX-License-Identifier: GPL-3.0-or-later
"""Watchdog adapter boundary (ROADMAP D8, owner handoff section 5).

The space-exhaustion watchdog is developed separately and its interface
does not exist yet. This package holds only Guardian's side of the
boundary, and nothing in it guesses that interface:

adapter   Guardian's own signal vocabulary, the adapter protocol, and the
          default DisabledAdapter. A real adapter (written once the
          watchdog's interface is known and reviewed) translates its data
          into these signals and nothing else.
pause     what a signal can do: pause classes of write operations, and
          nothing more. Resuming needs an owner touch.

Guardian works the same with the adapter disabled (the default).
"""
