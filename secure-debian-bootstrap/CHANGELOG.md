# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-06

Initial release.

### Added

- **Evidence-based platform detection** for Termux, Debian, Ubuntu, Kali
  (including Kali Purple), Parrot OS, MX Linux, and generic Debian-derived
  systems, with a confidence score, recorded evidence, and refusal on ambiguity.
- **Repository audit** covering APT hooks, proxies, trust bypass, foreign and
  duplicate repositories, development suites, pinning, held packages, custom
  transport methods, unsafe symlinks, keyring ownership/permissions/expiry, and
  `dpkg --verify` mismatches. Existing configuration is parsed, never executed.
- **Verified backups** with SHA-256 manifests, symlinks archived as symlinks,
  recorded ownership/mode/mtime, and platform identity metadata. Backups are
  never overwritten and never deleted by this tool.
- **Quarantine** that copies material aside and checksums it before disabling
  the live copy by rename. Package-owned files are reported, not quarantined.
  Third-party repositories are disabled and preserved, not destroyed.
- **Repository reconstruction** from reviewable templates with provenance
  metadata, an official-host allowlist, and suite/component preservation.
- **Staged validation**: the rebuilt configuration is exercised with the real
  apt via `APT_CONFIG` before activation. Nothing is activated if validation
  fails; the staging tree and transcript are preserved.
- **Atomic activation** with automatic restore from backup on partial failure.
- **Verified rollback** with checksum verification, platform-identity checks,
  manifest path re-validation, and symlink-safe restore.
- **Baseline hardening**: conservative, reversible, platform-gated controls,
  written as drop-in files only. Report-only by default; installs no packages
  and never changes firewall rules.
- Execution modes `--audit` (default), `--dry-run`, `--backup-only`,
  `--repair-repositories`, `--validate-repositories`,
  `--apply-baseline-hardening`, `--full`, `--rollback`, `--report`,
  `--list-backups`, plus `--non-interactive`, `--yes`, `--strict`,
  `--verbose`, `--debug`, `--sys-root`, `--state-dir`, `--no-network`,
  `--allow-secondary-template`, `--use-archive-repositories`.
- Human log, JSONL event log, findings stream, plan, applied-change record,
  validation transcript, and text/JSON reports per run.
- Resumable, idempotent stages via completion markers; exclusive locking via
  `flock` with an atomic-`mkdir` fallback.
- Test suite of 167 fixture-driven assertions that never touch the host, and
  `tools/shellcheck.sh` enforcing project safety gates.
- Documentation: architecture, threat model, supported platforms, repository
  recovery, rollback, operator guide, and a full research-source record.

### Security

- Never uses `apt-key`, `[trusted=yes]`, `AllowUnauthenticated`,
  `AllowInsecureRepositories`, keyserver fetches, `curl | sh`, `eval`,
  `sudo sh -c`, or `sudo -E`.
- Never mixes repositories across distributions, and never moves a system
  between releases or channels.
- `--yes` cannot override ambiguous detection, EOL releases, failed validation,
  unsafe paths, missing backups, or unverified templates.
- Proxy credentials, tokens, and private-key material are redacted from every
  output stream. No telemetry, no uploads, no persistence.

### Known limitations

- Debian and MX Linux repository templates are `secondary` confidence: this
  build could not reach `debian.org`, `mxlinux.org`, or `mxrepo.com` (blocked by
  the build environment's egress policy), so activating them requires
  `--allow-secondary-template`. See `docs/research-sources.md` §2.
- Parrot's archive keyring filename is unverified; the tool reports the keyring
  instead of writing an unsubstantiated `Signed-By`.
- No CIS/STIG conformance is claimed or cited.
- Extended attributes and ACLs are recorded but not re-applied on restore.
