# Security Policy

## Scope

`secure-debian-bootstrap` is a defensive recovery tool. It performs no remote
scanning, no exploitation, no persistence, and no network transmission of local
data.

## Reporting a vulnerability

Report security issues through the repository's issue tracker, or privately to
the maintainer if the issue would put users at risk before a fix is available.
Include the platform, the exact command, and the run directory contents
(`report.txt`, `events.jsonl`) with anything sensitive removed — note that the
tool already redacts proxy credentials, tokens, and key material from its own
output.

## What counts as a vulnerability here

This project's security properties are testable. A defect in any of these is a
vulnerability, not a bug:

- A write outside the detected platform's declared write roots (in particular:
  Termux writing to `/etc/apt`, or a non-Termux system writing under `$PREFIX`).
- Any path traversal or symlink escape during backup, quarantine, activation,
  or rollback.
- Executing, sourcing, or evaluating any content found in an APT configuration
  directory.
- Emitting `trusted=yes`, `AllowUnauthenticated`, `AllowInsecureRepositories`,
  or otherwise weakening signature verification.
- Activating a configuration that failed staged validation.
- Modifying the system without a verified backup.
- `--yes` overriding a refusal it is documented as unable to override.
- Repository definitions from one distribution appearing in another's
  configuration (excepting MX Linux's documented, legitimate use of Debian
  archives).
- Credentials, tokens, or key material appearing unredacted in any log, event
  stream, or report.
- Any outbound transmission of local data.

## What is out of scope

- An adversary who already holds persistent root or kernel-level control on the
  target. No shell script is a meaningful defence there; the tool documents this
  rather than implying otherwise.
- Downgrade or freeze attacks beyond what apt itself detects via `Release` file
  `Valid-Until`.
- The security of third-party repositories the operator chooses to re-enable
  after a repair.
- Vulnerabilities in apt, dpkg, gpg, or the distributions themselves.

## Verifying the properties yourself

```sh
./tools/test.sh         # asserts platform isolation, path safety, dry-run purity,
                        # backup-before-modify, rollback traversal refusal
./tools/shellcheck.sh   # gates: no eval, no curl|sh, no apt-key, no trusted=yes,
                        # no sudo sh -c, no sudo -E, no unguarded rm -rf
```

## Supported versions

The latest release on the default branch is supported.
