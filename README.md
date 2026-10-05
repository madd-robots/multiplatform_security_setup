# multiplatform_security_setup
A secure Bash toolkit for Debian-based systems and Termux. It audits, backs up, repairs, and validates package repositories, quarantines suspicious settings, supports rollback, and applies optional baseline hardening without changing the system during development.

## Projects

- [`mx_usb_airlock/`](mx_usb_airlock/README.md): MX Linux USB transfer airlock (V1.1). A trusted Android/Termux app signs (minisign) and encrypts (age) an approved PowerShell package. The MX airlock ingests it read-only from the transport USB, verifies the signature and every hash before and after decryption, stages it, and writes it to a separate clean USB whose entire filesystem is then verified. Read [`SECURITY_MODEL.md`](mx_usb_airlock/SECURITY_MODEL.md) before use.
- [`guardian_hub/`](guardian_hub/README.md): Guardian USB Encryption Hub. Stages 1 and 2 of 9 are done: the foundation library (canonical serialization, safe names, private I/O, structured logging) and the Linux security runtime (privileged broker, sandboxed per-job workers, kernel-verified IPC identity, default-deny capabilities). See [`ROADMAP.md`](guardian_hub/ROADMAP.md) for stage status and the design review.
