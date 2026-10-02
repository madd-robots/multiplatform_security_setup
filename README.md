# multiplatform_security_setup
A secure Bash toolkit for Debian-based systems and Termux. It audits, backs up, repairs, and validates package repositories, quarantines suspicious settings, supports rollback, and applies optional baseline hardening without changing the system during development.

## Projects

- [`mx_usb_airlock/`](mx_usb_airlock/README.md): MX Linux USB transfer airlock. Moves a small set of text recovery files (for example PowerShell hardening scripts) from an untrusted USB drive through a read-only ingest and a local quarantine onto a clean USB drive. The two drives are never attached at the same time, and the written files are verified afterwards. Read [`SECURITY_MODEL.md`](mx_usb_airlock/SECURITY_MODEL.md) before use.
