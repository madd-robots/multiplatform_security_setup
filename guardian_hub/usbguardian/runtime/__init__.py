# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 2 security runtime (POSIX): broker, isolated workers, IPC, authorization.

    client --(Unix socket, SO_PEERCRED)--> broker --(pipes)--> worker
                                             |
                                       authorization
                                       (default deny)

The broker is the only component that holds privileges.  Untrusted data
(device metadata, filesystem contents, files from media) is parsed only in
short-lived worker processes with dropped privileges and resource limits.
"""
