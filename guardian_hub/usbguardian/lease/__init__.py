# SPDX-License-Identifier: GPL-3.0-or-later
"""D5: renewable offline authorization leases for spinoffs.

records   request, lease and revocation documents and their digests
machine   machine identity binding (a digest of DMI and machine-id values)
spinoff   the spinoff's local lease state, its own key, and the ACTIVE gate
issuer    Guardian Main: issue, renew, reissue and revoke, with generations

A lease is authority to start protected operations (intake, writing
transfers, destructive device work). It is never needed to verify or
release data that already exists: authorization is separate from recovery.
"""
