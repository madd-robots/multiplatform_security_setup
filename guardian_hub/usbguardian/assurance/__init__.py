# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 8: advanced device assurance.

facts      what a device exposes, what cannot be verified, inconsistent claims
drives     registry of Guardian drives that passed erase-verification (D4 step 5)
reports    assurance, erase-verification and artifact reports: stored, recorded in
           the audit ledger, signable by the owner, verifiable on another instance
artifacts  verification of files against an owner-signed list of trusted hashes
service    broker operations
"""
