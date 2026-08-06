# Supported Platforms

Legend for **Repair**:

- **auto** — `--repair-repositories` can rebuild and activate after validation.
- **flagged** — rebuild is implemented but activation additionally requires
  `--allow-secondary-template`, because this build could not verify the
  repository facts against a vendor-primary source (see
  `docs/research-sources.md`).
- **audit-only** — the tool audits, backs up, and reports; it refuses to rebuild.

| Platform | Detect | Repair | Template confidence | Format written | Keyring model |
| --- | --- | --- | --- | --- | --- |
| Termux (Android) | yes | auto | `primary` | legacy `sources.list` | `trusted.gpg.d` symlinks into `$PREFIX/share/termux-keyring` |
| Kali Linux (incl. Kali Purple) | yes | auto | `primary` | deb822 `kali.sources` (≥2026.2 or if present), else legacy | `Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg` |
| Parrot OS | yes | auto | `primary` (repo lines) | legacy `parrot.list` | vendor keyring in `trusted.gpg.d`, reported not rewritten |
| Ubuntu | yes | auto | `primary` | deb822 `ubuntu.sources` | `Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg` |
| Debian | yes | flagged | `secondary` | deb822 `debian.sources` | `Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg` |
| MX Linux | yes | flagged | `secondary` | legacy `mx.list` + `debian.list` + `debian-stable-updates.list` | vendor keyring in `trusted.gpg.d`, reported not rewritten |
| Other Debian-derived | yes (as `generic-debian`) | audit-only | n/a | none | n/a |
| Ambiguous / unknown | detection stops | none | n/a | none | n/a |

## Platform boundaries

### Termux (Android)

- All paths are under `$PREFIX` (typically
  `/data/data/com.termux/files/usr`). The tool **never** writes to `/etc/apt`
  on Termux; `tests/test-path-safety.sh` asserts this.
- `sudo` is neither assumed nor requested. If a `sudo` binary exists (rooted
  device, `tsu`), it is reported but not used.
- No systemd, no kernel parameters, no firewall, no PAM, no bootloader, no
  system services — Android does not permit these from Termux and the tool
  records them as `unsupported_on_platform` rather than attempting them.
- Shared storage (`/sdcard`, `~/storage/*`) does not preserve Unix ownership or
  permission bits. Backups are never written there by default and the tool warns
  if `SDB_STATE_DIR` is pointed at shared storage.
- Repositories: `termux-main` (`stable main`) is the baseline. `termux-root` and
  `termux-x11` are preserved if already present but never added.
- Package manager: `apt`/`dpkg` are used directly for inspection. `pkg` is
  detected and reported; mirror switching is left to `termux-change-repo`.

### MX Linux

- Init may be **SysVinit or systemd** (MX 25.1 ships both). Init is detected;
  systemd-only controls are skipped with a recorded reason.
- MX legitimately combines MX repositories **with** Debian stable repositories.
  Debian archive entries are therefore *expected* on MX and are not flagged as
  foreign — unlike on Kali or Parrot.
- MX repository files are preserved in structure (`mx.list`, `debian.list`,
  `debian-stable-updates.list`); MX package-signing configuration is never
  removed. MX tools (`mx-repo-manager` and friends) are not replaced or
  interfered with.
- The MX mirror host discovered on the system is preserved; the template host is
  a fallback only.

### Kali Linux / Kali Purple

- Rolling is preserved. The detected suite (`kali-rolling` or
  `kali-last-snapshot`) is carried into the rebuilt configuration; the tool never
  switches branches.
- Debian archive entries on Kali are **foreign** and are disabled-and-preserved,
  never merged.
- Kali Purple is Kali, not a separate distribution: it is detected as `kali` with
  a `purple` variant flag, and no attempt is made to convert it to another
  branch, to Debian, or to Ubuntu.
- Security tooling is never removed. Server-oriented hardening that would impede
  an authorized security-testing workstation (e.g. restrictive outbound firewall
  defaults, `net.ipv4.ip_forward=0`, promiscuous-mode restrictions) is
  **off by default** on Kali and requires explicit opt-in.
- `kali-experimental` / `kali-bleeding-edge` are preserved if present, never
  added; the operator is pointed at `kali-tweaks`.

### Parrot OS

- The upstream three-line structure is preserved: `parrot` (main),
  `parrot-security` via the `deb.parrot.sh/direct/` host, and optional
  backports. The security entry's `direct` host is preserved exactly — upstream
  explicitly warns against serving security updates from mirrors.
- `echo-backports` is written **disabled** by default (documented deviation);
  enable with `SDB_PARROT_ENABLE_BACKPORTS=1`.
- Kali and Debian repository definitions are never substituted in.
- Security tools are never removed for looking unusual.

### Ubuntu

- The detected release codename is preserved. No interim↔LTS movement.
- `-proposed`, `-devel`, and development-series suites are refused as repair
  targets; if present they are reported and preserved-disabled.
- The existing component selection is preserved (a `main universe` system stays
  `main universe`).
- Security stanza always points at `security.ubuntu.com`.

### Debian

- Suite must equal the detected codename. `testing`, `unstable`, `sid`,
  `experimental` are refused as repair targets.
- `-security` uses `security.debian.org/debian-security` with the
  `<codename>-security` suite.
- Repair is **flagged** (`--allow-secondary-template` required) because the
  shipped `debian.sources` content could not be verified against debian.org from
  this build environment.

### Generic Debian-derived

Reached when `ID_LIKE` contains `debian` (or dpkg/apt are present) but `ID` is
not one of the supported set. The tool will detect, audit, inventory, back up,
quarantine, and report — and will **refuse** `--repair-repositories`, because no
verified official repository definition exists for that distribution in this
project. Adding one means adding a `templates/<id>/` directory with a
`TEMPLATE.meta` recording its source, plus a `lib/platforms/<id>.sh`; no core
code changes are required.

## Release status handling

Release status is computed at run time from the **target host's**
`/usr/share/distro-info/*.csv` when `distro-info-data` is installed, falling back
to a dated table in `lib/repository-audit.sh`.

| Status | Behaviour |
| --- | --- |
| `supported` | Repair permitted (subject to template confidence). |
| `eol` | Repair **stops**. Reason, EOL date, and supported upgrade targets are printed. Archive repositories (`old-releases.ubuntu.com`, `archive.debian.org`) are **not** used unless the operator explicitly passes `--use-archive-repositories`. |
| `prerelease` / `development` | Repair stops. |
| `unknown` | Repair stops (fail closed). |
| `rolling` | Repair permitted; suite preserved (Kali, Parrot). |

## Architecture support

Detection records `dpkg --print-architecture` and any
`dpkg --print-foreign-architectures`. Templates are architecture-neutral: no
`Architectures:` field is written unless the system already restricted it, in
which case the existing restriction is preserved.

## Minimum requirements

- `bash` ≥ 4.4 (associative arrays, `${var@Q}`, `local -n`). The launcher
  refuses to run on older bash with a clear message. Tested on 5.2.
- `coreutils` (`install`, `mktemp`, `sha256sum`, `stat`, `readlink`).
- `dpkg`/`apt` for full functionality; audit degrades gracefully without them.
- Optional: `flock` (locking), `gpg` (key inspection), `getfacl`/`setfacl` and
  `getfattr`/`setfattr` (extended attribute preservation), `distro-info`
  (release status), `shellcheck` (development only).
