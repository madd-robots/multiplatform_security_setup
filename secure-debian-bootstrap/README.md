# secure-debian-bootstrap

A defensive Bash toolkit that repairs a broken or tampered-with APT trust chain
on Debian-derived systems and Termux — or refuses, loudly, when it cannot do so
safely.

It is built to run on a machine that is **already** compromised, damaged,
misconfigured, or half-initialised. It treats the existing APT configuration as
hostile input: nothing found there is ever sourced, evaluated, or executed.

```sh
./bin/secure-debian-bootstrap            # audit only - changes nothing
```

## What it does

1. **Detects** the platform from multiple independent pieces of evidence and
   reports a confidence score with the evidence behind it. Ambiguity stops the run.
2. **Inventories** every APT configuration file with dpkg ownership, permissions,
   and checksums.
3. **Audits** for hooks, proxies, trust bypass, foreign repositories, duplicates,
   pinning, custom transport methods, unsafe symlinks, and compromised keyrings.
4. **Backs up** everything, with a SHA-256 manifest verified before any change.
5. **Quarantines** suspicious material by copying it aside and disabling it —
   never by deleting it.
6. **Rebuilds** a minimal, distribution-correct configuration from reviewable
   templates into a staging directory.
7. **Validates** that staging tree with the real apt before it is live.
8. **Activates** atomically, only after validation succeeds.
9. **Rolls back** from a verified backup, with the platform identity checked first.
10. **Optionally hardens** with conservative, reversible, platform-gated controls.

## Supported platforms

| Platform | Repair | Template confidence |
| --- | --- | --- |
| Termux (Android) | auto | primary |
| Kali Linux / Kali Purple | auto | primary |
| Parrot OS | auto | primary |
| Ubuntu | auto | primary |
| Debian | needs `--allow-secondary-template` | secondary |
| MX Linux | needs `--allow-secondary-template` | secondary |
| Other Debian-derived | audit only | — |

"Secondary" means this build could not read that distribution's repository
definitions from the vendor itself, so the tool **refuses to activate them**
without an explicit flag. See `docs/research-sources.md` for exactly what was
verified, from where, and when. Nothing in `templates/` was written from
memory.

## Safety properties

- Default mode is a non-destructive audit.
- No system change without an explicit apply mode; `--dry-run` for every one.
- A verified backup exists before anything is modified, or the stage refuses.
- Staged configuration is validated with the real apt before activation; if
  validation fails, **nothing** is activated and the staging tree is kept.
- Repositories are never mixed between distributions, and a system is never
  moved between releases or channels.
- Never uses `apt-key`, `[trusted=yes]`, `AllowUnauthenticated`, a keyserver
  fetch, or `curl | sh`. Never disables signature verification for any reason.
- `--yes` cannot override ambiguous detection, an EOL release, failed
  validation, an unsafe path, a missing backup, or an unverified template.
- Termux writes only under `$PREFIX` and never requests root; non-Termux
  systems never write under `$PREFIX`. Both are enforced by tests.
- Logs stay local. Nothing is uploaded, transmitted, or collected, and proxy
  credentials, tokens, and key material are redacted from every output stream.
- User data — git repositories, game projects, SSH private keys, browser
  profiles, Android app data — is outside the modification scope entirely.

## Quick start

```sh
# 1. look
./bin/secure-debian-bootstrap --audit --verbose

# 2. see exactly what a repair would do
sudo ./bin/secure-debian-bootstrap --repair-repositories --dry-run

# 3. do it
sudo ./bin/secure-debian-bootstrap --repair-repositories

# 4. undo it
sudo ./bin/secure-debian-bootstrap --rollback <backup-id>
```

On Termux, omit `sudo` — the tool does not use root there.

Backups and logs live in `/var/lib/secure-debian-bootstrap`
(`$PREFIX/var/lib/secure-debian-bootstrap` on Termux).

## Documentation

| Document | Contents |
| --- | --- |
| `docs/operator-guide.md` | Day-to-day usage, exit codes, risky flags, privileged operations |
| `docs/repository-recovery.md` | How the repair works, stage by stage, and its guarantees |
| `docs/rollback.md` | Rollback verification, what is restored, limits of assurance |
| `docs/architecture.md` | Module map, stage pipeline, staged-validation mechanism |
| `docs/threat-model.md` | Assets, adversaries, threats, mitigations, non-goals |
| `docs/supported-platforms.md` | Per-platform boundaries and release handling |
| `docs/research-sources.md` | Every repository fact, its source, date, and confidence |
| `examples/` | Real captured output: audit, dry run, repair, rollback, refusals |

## Development

```sh
./tools/test.sh         # 167 assertions, fixture-driven, never touches the host
./tools/shellcheck.sh   # ShellCheck + project safety gates
```

## Known limitations

- Debian and MX repository templates are `secondary` confidence (see above).
- Parrot's archive keyring filename could not be verified, so the tool reports
  the keyring rather than writing a `Signed-By` line it cannot substantiate.
- No CIS or STIG conformance is claimed; no benchmark was reachable to verify
  against, and none is cited.
- Downgrade attacks are detected only to the extent apt itself detects them.
- Extended attributes and ACLs are recorded in backups but not re-applied
  automatically on restore.
- Hardening never installs packages and never changes firewall rules.
- Against an adversary who already holds persistent root or kernel-level
  control, no shell script is meaningful. The report says so rather than
  implying otherwise; reinstall from verified media.

## License

GNU General Public License v3 — see `LICENSE`.
