# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 5 identity: YubiKey owner keys, trust log, owner assertions (ROADMAP D2, D3).

Owner keys are FIDO2 security-key SSH keys (``sk-ssh-ed25519``) created on
the YubiKeys. Signing needs a physical touch and no PIN. Verification needs
only public keys. Signatures use OpenSSH's SSHSIG format through
``ssh-keygen -Y``, which is available on Debian/MX, Termux and Windows.

sshkeys      public key parsing, key ids, allowed key types
sshsig       signing (client side, touch) and verification (sandboxed worker)
trust        hash-chained, signed trust log: genesis, enroll, revoke
enrollment   client-side builders for trust events
owner        per-request owner assertions (challenge, touch, one-shot grant)
"""
