# SPDX-License-Identifier: GPL-3.0-or-later
"""Worker entry point.  Run only by the broker, with python3 -I -B -S."""

import sys
from pathlib import Path

# -I removes the script directory from sys.path; add the package root back.
# Appended, not prepended, so nothing next to the package can shadow a
# standard library module.  The launcher has verified this tree.
sys.path.append(str(Path(__file__).resolve().parents[2]))

from usbguardian.runtime.worker import main  # noqa: E402

sys.exit(main(sys.argv))
