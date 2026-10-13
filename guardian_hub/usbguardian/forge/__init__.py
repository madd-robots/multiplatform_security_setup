# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 6 Guardian Forge: build, sign and track spinoff deployments.

A deployment is a Stage 4 package signed in its own namespace
(``guardian-deploy@v1``), so transfers and deployments can never be swapped
for each other. It carries:

    deployment.json   descriptor: instance id, platform, profile, capabilities,
                      trust anchor and head, issue time, code inventory
    trust.log         snapshot of the signed trust log (public keys only)
    code/...          the Guardian code files, byte for byte

A spinoff never receives signing authority. It holds public keys only, and
its profile can never include Forge capabilities.

profiles     platforms (and which are available) and capability profiles
descriptor   descriptor schema, code collection, descriptor construction
registry     Guardian Main's record of the deployments it built
service      broker operations forge.prepare / forge.write / forge.list / forge.retire
install      target side: verify a deployment against a pinned anchor and extract it
"""
