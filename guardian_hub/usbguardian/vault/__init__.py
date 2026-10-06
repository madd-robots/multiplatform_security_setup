# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 4 integrity vault: custody store, transfer packages, verified release.

Guardian attests custody, not provenance (ROADMAP D6). The bytes accepted at
intake are the integrity reference. They are never modified, and the
receiving Guardian releases them only after proving they are identical.

custody   intake into a private content-addressed store (SHA-256 + length)
package   transfer package format: write, read-back, verify
release   verify-then-release into a destination directory via staging
auth      signer/verifier interface; YubiKey implementations arrive in Stage 5
"""
