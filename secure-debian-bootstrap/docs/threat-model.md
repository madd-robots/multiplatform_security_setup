# Threat Model

## 1. What this project is

`secure-debian-bootstrap` runs on a machine whose package-management trust chain
may already be broken. Its job is to make that chain **correct and verifiable
again**, or to stop and say why it cannot.

It is a *defensive recovery* tool. It performs no scanning of remote hosts, no
exploitation, no persistence, and no network transmission of local data.

## 2. Assets

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | APT trust anchors (`/usr/share/keyrings`, `/etc/apt/keyrings`, `trusted.gpg.d`, Termux `$PREFIX/share/termux-keyring`) | Compromise here means arbitrary code execution as root at the next `apt upgrade`. |
| A2 | Repository definitions (`sources.list`, `sources.list.d/*`) | Redirection to a hostile archive. |
| A3 | APT behaviour configuration (`apt.conf`, `apt.conf.d/*`, `preferences.d/*`) | `DPkg::Pre-Invoke` hooks, proxies, and pinning are code-execution and downgrade primitives. |
| A4 | The backups and manifests this tool creates | If forgeable, rollback becomes an attack. |
| A5 | The operator's data: git repositories, game projects, SSH private keys, browser profiles, Android shared storage | Explicitly out of the modification scope. |
| A6 | System integrity outside APT: kernel, bootloader, disk encryption, firmware | Explicitly out of scope; never touched. |

## 3. Adversaries and positions

| # | Adversary | Position assumed |
| --- | --- | --- |
| T1 | Prior attacker | Already wrote to `/etc/apt/**` before this tool ran. Content there is **untrusted input**. |
| T2 | Local unprivileged user | Can write world-writable dirs, race `/tmp`, plant symlinks, and win TOCTOU windows against a root-run script. |
| T3 | Network attacker | Controls DNS/transport; can serve a mirror, strip TLS, or hold back updates. |
| T4 | Malicious mirror | Serves valid-looking but hostile metadata; may roll back to older vulnerable versions. |
| T5 | The operator's own mistake | Runs `--full --yes` on the wrong machine, or on an EOL/ambiguous system. |
| T6 | This tool itself | A bug in it is a root-level integrity bug. |

Explicitly **out of model**: an attacker who already has persistent root and
kernel-level control. Nothing a shell script does is meaningful there — the
project says so rather than implying otherwise (see `docs/rollback.md`,
"limits of assurance").

## 4. Threats and mitigations

### T1 — hostile existing APT configuration

| Threat | Mitigation | Where |
| --- | --- | --- |
| Shell code hidden in an APT config file that a naive repair script `source`s | Nothing under an APT directory is ever sourced, `eval`'d, or executed. Config is parsed line-wise with `read -r` into arrays. | `lib/repository-audit.sh`, `lib/common.sh` (no `eval` anywhere; enforced by `tools/shellcheck.sh` and a grep gate in `tools/test.sh`) |
| `DPkg::Pre-Invoke` / `Post-Invoke` / `APT::Update::Pre-Invoke` hooks | Detected, reported as `finding=apt_hook`, quarantined (copied, then disabled) — never executed. | `lib/repository-audit.sh:sdb_audit_apt_conf` |
| `Acquire::http::Proxy` pointing at an interception proxy | Detected and reported; proxy **credentials are redacted** from every log. | `lib/repository-audit.sh`, `lib/logging.sh:sdb_redact` |
| `[trusted=yes]`, `Trusted: yes`, `AllowInsecureRepositories`, `AllowUnauthenticated` | Detected as high-severity findings. Never written by this tool under any flag. | `lib/repository-audit.sh`, `lib/repository-rebuild.sh` |
| Custom APT transport methods in `/usr/lib/apt/methods` | Presence of non-dpkg-owned methods is reported. Not auto-removed (removal could break a legitimate transport). | `lib/repository-audit.sh:sdb_audit_methods` |
| Rogue keyring dropped into `trusted.gpg.d` | Every keyring is listed with `dpkg -S` ownership, fingerprint, and expiry; unowned keyrings are reported and quarantined on repair. | `lib/package-trust.sh` |
| Pinning that holds a package at a vulnerable version | `preferences.d` entries and `apt-mark showhold` output are reported. | `lib/repository-audit.sh:sdb_audit_pinning` |

### T2 — local attacker racing a root-run script

| Threat | Mitigation | Where |
| --- | --- | --- |
| Symlink swap on a file we back up or restore | Backups use `--no-dereference`; symlinks are archived as symlinks. Restore refuses to follow a symlink to a target outside the recorded root. | `lib/backup.sh`, `lib/rollback.sh:sdb_rollback_restore_one` |
| Symlink/dir-traversal inside an archive (`../../etc/shadow`) | Every manifest path is validated against `sdb_path_is_within` **and** rejected if it contains `..`, is absolute, or is empty, before any write. | `lib/common.sh:sdb_manifest_path_is_safe` |
| `/tmp` race on staging or work directories | Work dirs are created with `mktemp -d` under a `0700` state directory, never a world-writable path; `umask 077` is set at entry. | `lib/common.sh:sdb_init_workspace` |
| Two invocations racing each other into a half-applied state | Exclusive `flock` on a lock file for the whole modifying run; if `flock` is absent, an atomic `mkdir` lock with PID liveness check. | `lib/common.sh:sdb_acquire_lock` |
| Partially written config activated on crash | New files are written to a temp name in the *destination* directory and `mv`'d into place (same-filesystem atomic rename). Never `cp` over a live file. | `lib/common.sh:sdb_install_file` |

### T3/T4 — network and mirror adversaries

| Threat | Mitigation | Where |
| --- | --- | --- |
| Repair points APT at an attacker's archive | URIs come only from reviewable files under `templates/`, never from network input, never from the untrusted existing config without classification. Any host not on the platform's official-host allowlist stops the repair. | `lib/repository-rebuild.sh:sdb_uri_is_official` |
| Signature checking silently disabled to "make it work" | There is no code path that disables verification. Validation failure is terminal for that stage. | `lib/repository-validate.sh` |
| Unsigned or mismatched `Release` file | `apt-get update` against the **staged** config is run with insecure repositories disallowed; `NO_PUBKEY`, `not signed`, `Release file ... not valid`, and codename-mismatch conditions are parsed and treated as failures. | `lib/repository-validate.sh:sdb_validate_apt_update` |
| Silent downgrade/rollback attack via mirror | Detected only to the extent APT itself detects it (`Release` file `Valid-Until`); documented as a limitation. | `docs/repository-recovery.md` |
| Expired signing key | Key expiry is checked with `gpg --show-keys` where available and reported before activation. | `lib/package-trust.sh:sdb_key_expiry_report` |

### T5 — operator error

| Threat | Mitigation |
| --- | --- |
| Running on an unrecognised or ambiguous system | Detection emits a confidence score with evidence; below threshold, **all modifying stages refuse**, including under `--yes`. |
| `--yes` used as a blanket override | `--yes` answers *routine* prompts only. It cannot override: ambiguous detection, EOL/unsupported release, failed validation, unsafe path, missing/failed backup, or a `secondary`-confidence template. Those require their own explicit flags or fail. |
| `--non-interactive` in automation, hitting a decision | Fails closed with a non-zero exit and a machine-readable reason. |
| Silent release migration (stable→testing, LTS→interim, Kali branch switch) | The rebuilt suite must equal the detected suite; a mismatch is an error, not a "fix". |
| Losing the only backup | Backups are never deleted by this tool. Retention pruning is not implemented, by choice. |

### T6 — bugs in this tool

| Threat | Mitigation |
| --- | --- |
| Destructive glob or unquoted expansion | `set -Eeuo pipefail`, ShellCheck gate in CI/`tools/shellcheck.sh`, arrays everywhere, no `rm -rf` without `sdb_safe_remove` path validation. |
| Wrong platform's paths written | Every write goes through `sdb_guard_write_root`, which asserts the target is inside the *detected platform's* configured root. Tests assert Termux never writes under `/etc/apt` and non-Termux never writes under `$PREFIX`. |
| Changes applied before backup | `sdb_require_backup` is called at the top of every modifying stage; the stage aborts if the backup id is unset or its manifest fails verification. |
| Unreviewable behaviour | Every action emits a JSONL event; `--dry-run` prints the full plan and asserts zero writes. |

## 5. Trust boundaries

```
 ┌──────────────────────────── untrusted ────────────────────────────┐
 │ existing /etc/apt/** (or $PREFIX/etc/apt/**), keyrings, hooks,    │
 │ preferences, methods, environment variables, PATH, network        │
 └───────────────────────────────────────────────────────────────────┘
                │ parsed, never executed; classified; quarantined
                ▼
 ┌──────────────────────── this project (semi-trusted) ──────────────┐
 │ lib/*.sh + templates/*  — reviewable, version-controlled,         │
 │ no network fetch of executable content, no eval                   │
 └───────────────────────────────────────────────────────────────────┘
                │ atomic writes, guarded roots, staged validation
                ▼
 ┌──────────────────────────── trusted ──────────────────────────────┐
 │ distribution keyring packages, dpkg database, apt binary          │
 └───────────────────────────────────────────────────────────────────┘
```

The keyring **packages** are trusted; the keyring **files on disk** are not
(they may have been replaced), which is why ownership and fingerprints are
verified rather than assumed.

## 6. Privilege model

Discovery, audit, inventory, template rendering, and staged validation are
designed to run unprivileged wherever the files are readable. Privilege is
requested only for: reading root-only files, writing under `/etc/apt`,
activating configuration, and running the optional hardening controls.

- The privileged command set is enumerated in `docs/operator-guide.md`.
- `sudo` is invoked with an explicit argument vector — never
  `sudo sh -c "<interpolated string>"`.
- Environment is not preserved across `sudo` (no `-E`).
- On Termux, root is never assumed or requested.

## 7. Non-goals

- Not an anti-virus, IDS, or rootkit remover. ClamAV/rkhunter integration, where
  offered, is *installation and reporting only*, and the docs state plainly that
  they do not detect all Linux threats.
- Not a compliance tool. No CIS/STIG claim is made (see `research-sources.md` §3.9).
- Not a mirror selector, not a package installer for third-party software.
- Not a defence against an already-persistent kernel-level compromise. If A1 was
  compromised by an adversary with root, the only sound recovery is
  reinstallation from verified media; the tool says so in its report rather than
  offering false assurance.
