# Repository Recovery

This is the highest-priority subsystem. It assumes the existing APT
configuration may be hostile and rebuilds a minimal, distribution-correct one
that is proven before it is used.

## The five stages

### 1. Inventory

`lib/inventory.sh` enumerates every path the platform cares about and records,
per file: type, dpkg ownership, mode, owner/group, size, symlink target, and
SHA-256. Locations covered:

| Normal Debian-style | Termux |
| --- | --- |
| `/etc/apt/sources.list` | `$PREFIX/etc/apt/sources.list` |
| `/etc/apt/sources.list.d/` | `$PREFIX/etc/apt/sources.list.d/` |
| `/etc/apt/apt.conf`, `apt.conf.d/` | `$PREFIX/etc/apt/apt.conf.d/` |
| `/etc/apt/preferences`, `preferences.d/` | — |
| `/etc/apt/trusted.gpg`, `trusted.gpg.d/` | `$PREFIX/etc/apt/trusted.gpg.d/` |
| `/etc/apt/keyrings/`, `/usr/share/keyrings/` | `$PREFIX/share/termux-keyring/` |
| `/etc/apt/auth.conf`, `auth.conf.d/` | — |

Each file is classified as `distro-repo`, `third-party`, `pkg-managed`,
`admin`, `keyring`, `suspicious`, or `unknown`.

### 2. Audit

`lib/repository-audit.sh` parses repository definitions (both the one-line and
deb822 forms) **without executing anything** and raises findings:

| Finding | Severity | Meaning |
| --- | --- | --- |
| `repo_trusted_yes` | high | `[trusted=yes]` / `Trusted: yes` — verification off |
| `apt_verification_disabled` | high | `AllowUnauthenticated` / `AllowInsecureRepositories` |
| `apt_hook` | high | `DPkg::Pre-Invoke` / `Post-Invoke` — APT runs a shell command |
| `apt_conf_executable` | high | a config file with the executable bit set |
| `apt_dir_override` | medium | `Dir::` overrides in apt.conf |
| `apt_proxy` | medium | proxy configured (credentials redacted in all output) |
| `repo_cross_distribution` | high | another distribution's archive (platform-aware) |
| `repo_development_suite` | high | `sid`/`testing`/`unstable` on a stable system |
| `repo_proposed_suite` | high | `-proposed` / `-devel` |
| `repo_duplicate` | medium | the same URI+suite defined twice |
| `repo_suite_mismatch` | medium | a suite that is not the detected release |
| `apt_pinning` | medium | pinning can hold a package at a vulnerable version |
| `package_held` | medium | `apt-mark showhold` entries |
| `apt_custom_method` | high | a transport method in `/usr/lib/apt/methods` owned by no package |
| `unsafe_symlink` | high | a symlink escaping the APT configuration root |
| `keyring_unowned` / `keyring_writable` / `keyring_owner` | high | a compromised-looking trust anchor |
| `key_expired` / `key_revoked` | high | from `gpg --show-keys` |
| `modified_package_file` | high | `dpkg --verify` disagrees with the package |
| `legacy_trusted_gpg` | medium | keys trusted for every repository |

**Nothing found here is ever executed, sourced, or evaluated.**

### 3. Backup

`lib/backup.sh` archives everything inventoried into
`$SDB_STATE_DIR/backups/<backup-id>/` with:

- `files/` — the archived tree, symlinks archived **as symlinks**
  (`cp --no-dereference`, so a swapped link is never followed)
- `manifest.tsv` — relpath, type, mode, owner, group, mtime, link target
- `manifest.sha256` — checksums, verified immediately after creation
- `meta.json` — platform identity, so a rollback cannot be applied to the wrong OS
- `xattrs.txt` / `acls.txt` — when `getfattr` / `getfacl` are available

A backup is never overwritten and is never deleted by this tool. Every
modifying stage calls `sdb_require_backup`, which re-verifies the checksums and
aborts if they do not match.

### 4. Quarantine

Quarantine copies first, then disables — it never destroys.

1. The file is copied into `$SDB_STATE_DIR/quarantine/<run-id>/files/` and
   checksummed.
2. Only then is the live copy renamed to `<name>.sdb-quarantined`, which APT
   ignores (it reads only `*.list`/`*.sources` in `sources.list.d`, and applies
   run-parts naming rules in `apt.conf.d`).
3. The rename is recorded so `sdb_quarantine_restore` can undo it.

Policy limits what is quarantined automatically:

- **Only** high-severity findings inside the APT configuration root.
- **Never** a file owned by an installed package — a modified package file is
  reported instead, because the correct repair is reinstalling the package.
- Third-party repositories are **disabled and preserved**, not destroyed, so
  the baseline repair happens against vendor archives only and the operator can
  deliberately re-enable them afterwards.

### 5. Rebuild → validate → activate

Rebuild renders `templates/<platform>/` into
`$SDB_RUN_DIR/staging/etc/apt/` — a complete miniature APT root. The live
configuration is not touched at this point.

Generated content is checked before it goes near apt:

- Any `trusted=yes` or `AllowUnauthenticated` in output is a **fatal bug**, not
  a warning — the run aborts.
- Every URI must match the platform's official-host allowlist
  (`sdb_platform_<id>_official_hosts`). A host outside it stops the repair.
- Every `Signed-By` keyring must exist (resolved against `--sys-root`).
- Any unsubstituted `@PLACEHOLDER@` aborts the run.

Then validation runs the real apt against the staging tree. Passing only
`-o Dir::Etc=…` is **not** sufficient isolation: apt has already loaded the
host's `apt.conf.d` by the time command-line options apply. This project
therefore writes a staged config file and points `APT_CONFIG` at it — verified
against apt 2.8.3 (host hooks visible with `-o` alone, none via `APT_CONFIG`).

Validation covers: deb822/one-line syntax, release and codename consistency,
`Signed-By` keyring existence and permissions, duplicate definitions,
`apt-config dump` review (hooks, verification-weakening options), staged
`apt-get update` with insecure repositories disallowed, and — only after a
successful update — `apt-get indextargets`.

`apt-get update` output is parsed for `NO_PUBKEY`, `is not signed`, invalid or
expired `Release` files, codename/suite mismatch, and unexpected metadata
changes (possible redirection). Network failures are distinguished from
repository failures, and a network failure still prevents activation — the
configuration was not proven.

Only if every check passes does activation copy files into place, one atomic
rename at a time. If any file fails to install, the run restores the backup
and exits.

## Guarantees

The repair will **never**:

- use `apt-key`, `[trusted=yes]`, `AllowUnauthenticated`,
  `AllowInsecureRepositories`, or disable signature checking in any way
- download a key from a keyserver, or fetch anything executable
- pipe `curl` into a shell
- mix Debian, Ubuntu, Kali, Parrot, MX, or Termux repositories (with the single
  documented exception that MX legitimately uses Debian archives)
- move a system between releases or channels — the rebuilt suite must equal the
  detected suite, or validation fails
- convert stable to testing/unstable/rolling
- replace a vendor kernel or desktop stack
- add a third-party repository
- use an unvalidated mirror
- delete a backup or a quarantine

## End-of-life releases

Release status is computed from the **target host's** `distro-info-data` when
present, falling back to a dated table in `lib/repository-audit.sh`.

On an EOL release the repair **stops** and prints the exact condition, the EOL
date, and the supported options. Archive repositories
(`old-releases.ubuntu.com`, `archive.debian.org`) are not used unless the
operator explicitly passes `--use-archive-repositories`. `--yes` does not
override this.

## Template confidence

Each `templates/<platform>/TEMPLATE.meta` records `confidence`:

- `primary` — taken from the vendor's own published file or documentation
  source (Termux, Kali, Parrot, Ubuntu).
- `secondary` — structurally plausible but not read from the vendor by this
  build (Debian, MX Linux — see `docs/research-sources.md` §2 for why).

A `secondary` template **refuses to activate** without
`--allow-secondary-template`. This is deliberate: writing an unverified archive
URI is precisely the failure this tool exists to prevent.
