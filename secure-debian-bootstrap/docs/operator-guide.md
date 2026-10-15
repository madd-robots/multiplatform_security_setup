# Operator Guide

## Install

There is nothing to install. Clone the repository and run the launcher; it
locates its own libraries relative to itself.

```sh
git clone <repo> && cd secure-debian-bootstrap
./bin/secure-debian-bootstrap --help
```

Requirements: bash ≥ 4.4 and coreutils. Everything else is optional and
degrades gracefully (see `docs/supported-platforms.md`).

## The first thing to run

```sh
./bin/secure-debian-bootstrap
```

That is audit mode — the default. It reads, reports, and changes nothing. Read
the report before doing anything else.

## Commands you will actually use

```sh
# 1. What is wrong with this system?
./bin/secure-debian-bootstrap --audit --verbose

# 2. What exactly would a repair do? (changes nothing)
sudo ./bin/secure-debian-bootstrap --repair-repositories --dry-run

# 3. Do it. Takes a verified backup, stages, validates, then activates.
sudo ./bin/secure-debian-bootstrap --repair-repositories

# 4. Undo it.
sudo ./bin/secure-debian-bootstrap --rollback <backup-id>

# 5. Where is everything?
./bin/secure-debian-bootstrap --list-backups
./bin/secure-debian-bootstrap --report          # re-print the last report
```

On **Termux**, drop the `sudo` — the tool neither uses nor requests root there:

```sh
./bin/secure-debian-bootstrap --audit
./bin/secure-debian-bootstrap --repair-repositories --dry-run
./bin/secure-debian-bootstrap --repair-repositories
```

## Where things are

| What | Path |
| --- | --- |
| Runs, logs, reports | `/var/lib/secure-debian-bootstrap/runs/<run-id>/` |
| Backups | `/var/lib/secure-debian-bootstrap/backups/<backup-id>/` |
| Quarantine | `/var/lib/secure-debian-bootstrap/quarantine/<run-id>/` |
| Termux equivalent | `$PREFIX/var/lib/secure-debian-bootstrap/…` |

Override with `--state-dir DIR`. On Termux, do **not** point it at shared
storage (`/sdcard`, `~/storage/*`): shared storage does not preserve Unix
ownership or permission bits, so backups taken there cannot be restored
faithfully. The tool warns and raises a finding if you do.

Per run you get: `run.log` (human), `events.jsonl` (machine), `detection.json`,
`inventory.tsv`, `findings.jsonl`, `plan.txt`, `applied.tsv`,
`validation.txt`, `report.txt`, `report.json`, and `staging/`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 2 | usage error |
| 3 | detection ambiguous or unsupported |
| 4 | preflight failure |
| 5 | backup missing or failed verification |
| 6 | staged validation failed — **nothing was activated** |
| 7 | refused: unsupported or EOL release |
| 8 | refused: unsafe path or symlink |
| 9 | refused: a decision was needed under `--non-interactive` |
| 10 | rollback failure |
| 11 | `--strict`: high-severity findings |
| 12 | another run holds the lock |

## What `--yes` does and does not do

`--yes` answers routine prompts. It **cannot** override:

- ambiguous or low-confidence platform detection
- an end-of-life, pre-release, or unknown release
- failed staged validation
- an unsafe path or a symlink escaping the configuration root
- a missing or unverifiable backup
- a `secondary`-confidence repository template

Each of those has its own explicit flag or requires manual work. That is the
design: a blanket "yes" must never be able to break a system.

`--non-interactive` fails closed — if a decision is required and cannot be made
safely, the run exits non-zero with the reason.

## Flags that carry real risk

| Flag | What you are accepting |
| --- | --- |
| `--allow-secondary-template` | Activating repository definitions this build could not verify against the vendor (Debian, MX). Read `templates/<platform>/` first. |
| `--use-archive-repositories` | Running an EOL release from archived packages that receive no security updates. |
| `--no-network` | The staged configuration is **not** proven to fetch and verify. Use only when you already know the archives are reachable. |
| `--sys-root DIR` | Operating on a chroot/fixture rather than the running system. The write guard follows it. |

## Privileged operations

The tool tries every filesystem operation unprivileged first and escalates only
when that fails, so a run inside `$PREFIX`, a user-owned state directory, or a
fixture never escalates at all. When it does escalate it prints the exact
command first. The complete privileged set is:

- `install -d` / `install -m` — create the state directory and write files
- `mv` — atomic activation and quarantine renames
- `cp` — archiving files into the backup
- `rm` — removing a temp file or an unsafe symlink at a restore destination
- `chmod` / `chown` / `touch` — restoring recorded permissions
- `apt-get update` — verifying the activated configuration
- `sshd -t` — validating an sshd drop-in before leaving it in place

It never runs `sudo sh -c "<string>"`, never uses `sudo -E`, and never
preserves the environment across the privilege boundary. On Termux it never
uses sudo at all.

## Baseline hardening

```sh
sudo ./bin/secure-debian-bootstrap --apply-baseline-hardening --dry-run
sudo ./bin/secure-debian-bootstrap --apply-baseline-hardening
```

Most controls are **report-only**. The ones that change anything write a single
drop-in file each (see `docs/rollback.md` for the undo table). Notably:

- **No packages are installed.** Missing tools (auditd, ClamAV, Lynis, AIDE,
  fail2ban) are reported with the command you would run, never installed
  automatically.
- **The firewall is never changed automatically** — a wrong rule disconnects a
  remote operator.
- **sshd hardening does not touch `PermitRootLogin` or
  `PasswordAuthentication`**, because changing those unattended can lock you
  out. What it does write is validated with `sshd -t`, and removed again if
  sshd rejects it. The running sshd is not reloaded for you.
- **SSH key permissions are reported, never modified.** The tool does not touch
  key material.
- On **Kali and Parrot**, intrusive controls (firewall, network sysctls, AIDE)
  are opt-in, because they break legitimate security-testing workflows.
- On **Termux**, controls Android does not permit are listed as unsupported
  with the reason, rather than attempted.

## Development

```sh
./tools/test.sh         # full suite; host-safe, fixture-driven
./tools/shellcheck.sh   # ShellCheck + project safety gates
```

`tools/shellcheck.sh` enforces gates ShellCheck cannot express: no `eval`, no
`curl | sh`, no `apt-key`, no emitted `trusted=yes`, no `sudo sh -c`, no
`sudo -E`, no unguarded `rm -rf`.

The project is ShellCheck-clean at `--severity=style`. The one documented
exception is a file-level `SC2034,SC2153` disable in the library files:
ShellCheck cannot see cross-file use in a sourced library, so globals set in one
file and read in another are reported as unused.

Bats is **not** required. The suite is plain bash so it runs anywhere the tool
runs, including Termux.

### Adding a platform

No core changes are needed:

1. `templates/<id>/` with the repository files and a `TEMPLATE.meta` recording
   `source`, `source_url`, `retrieved`, `confidence`, and `official_hosts`.
2. `lib/platforms/<id>.sh` implementing `…_roots`, `…_select_template`,
   `…_render_vars`, `…_prepare`, `…_foreign_origins`, `…_official_hosts`,
   `…_hardening_profile`, and optionally `…_preflight`, `…_optin_controls`,
   `…_unsupported_controls`, `…_symlink_allowlist`.
3. Detection scoring in `lib/detect-platform.sh:_sdb_corroborate`.
4. A fixture in `tests/fixtures/make-fixtures.sh` and assertions that the new
   platform does not mix repositories with any other.

Platform ids containing dashes are fine — `sdb_platform_fn` normalises them to
underscores in exactly one place.
