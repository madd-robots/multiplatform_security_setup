# Architecture

## Design rules

1. **One responsibility per module.** The launcher parses arguments and
   sequences stages; it contains no repository, backup, or hardening logic.
2. **Everything is rooted.** No module hardcodes `/etc/apt`. All filesystem
   access goes through roots resolved once by detection
   (`SDB_SYS_ROOT`, `SDB_APT_ETC`, `SDB_KEYRING_DIRS`, `SDB_STATE_DIR`), which
   makes the whole system testable against fixtures and makes Termux a
   configuration rather than a special case sprinkled through the code.
3. **Untrusted in, structured out.** Existing configuration is parsed into
   records; it is never sourced, evaluated, or executed.
4. **Plan, then apply.** Every modifying stage builds a plan of `sdb_plan_add`
   entries. `--dry-run` prints the plan and exits before the apply step. The
   same code path produces both, so the dry run cannot drift from reality.
5. **Fail closed.** Any unresolved question in a modifying stage is an error.

## Module map

```
bin/secure-debian-bootstrap      argument parsing, mode dispatch, stage sequencing, exit codes
lib/
  common.sh                      strict mode, path safety, atomic install, locking,
                                 workspace, plan/apply, privilege helpers, safe remove
  logging.sh                     levels, human log, JSONL event log, redaction
  detect-platform.sh             evidence-based detection -> SDB_PLATFORM/*, confidence
  preflight.sh                   environment sanity, required commands, writability, lock
  inventory.sh                   enumerate APT config, dpkg ownership, classification
  repository-audit.sh            findings: hooks, proxies, trust bypass, foreign repos,
                                 duplicates, pinning, methods, release status
  backup.sh                      timestamped backup + SHA-256 manifest + metadata
  quarantine.sh                  copy-then-disable suspicious material
  repository-rebuild.sh          render templates -> staging dir (never live)
  repository-validate.sh         validate staging with apt Dir:: overrides
  package-trust.sh               keyring inventory, ownership, fingerprints, expiry
  baseline-hardening.sh          conservative, reversible, platform-gated controls
  rollback.sh                    verified restore from a backup id
  reporting.sh                   human + JSON summary rendering
  platforms/<id>.sh              per-platform roots, template selection, boundaries
templates/<id>/                  reviewable repository definitions + TEMPLATE.meta
config/defaults.conf             tunables
tests/                           fixture-driven, host-safe
tools/                           shellcheck + test runners
```

## Stage pipeline

```
        ┌────────────┐
        │  preflight │  bash version, commands, lock, workspace, umask
        └─────┬──────┘
              ▼
        ┌────────────┐
        │   detect   │  evidence -> platform + confidence   ── ambiguous ─▶ STOP
        └─────┬──────┘
              ▼
        ┌────────────┐
        │ inventory  │  enumerate + classify every APT config file
        └─────┬──────┘
              ▼
        ┌────────────┐
        │   audit    │  findings + release status              (audit mode ends here)
        └─────┬──────┘
              ▼
        ┌────────────┐
        │   backup   │  copy + manifest + verify              ── verify fail ─▶ STOP
        └─────┬──────┘
              ▼
        ┌────────────┐
        │ quarantine │  copy suspicious material aside
        └─────┬──────┘
              ▼
        ┌────────────┐
        │  rebuild   │  render templates into STAGING (live untouched)
        └─────┬──────┘
              ▼
        ┌────────────┐
        │  validate  │  apt against STAGING via Dir:: overrides ── fail ─▶ STOP (keep staging)
        └─────┬──────┘
              ▼
        ┌────────────┐
        │  activate  │  atomic rename into place, per file
        └─────┬──────┘
              ▼
        ┌────────────┐
        │  harden    │  optional, platform-gated, reversible
        └─────┬──────┘
              ▼
        ┌────────────┐
        │   report   │  human + JSON + rollback instructions
        └────────────┘
```

Each stage writes a completion marker into the run's state directory
(`stages/<name>.done`), which is what makes stages independently **resumable**
and the whole run **idempotent**: a stage that finds its marker and observes the
same desired state is a no-op.

## Staged validation: how APT is tested without being activated

`lib/repository-rebuild.sh` renders into
`$SDB_RUN_DIR/staging/etc/apt/` — a complete miniature APT configuration root.
`lib/repository-validate.sh` then runs the real `apt-get`/`apt-cache` against it:

```
apt-get -o Dir::Etc="$STAGE/etc/apt" \
        -o Dir::Etc::sourcelist="$STAGE/etc/apt/sources.list" \
        -o Dir::Etc::sourceparts="$STAGE/etc/apt/sources.list.d" \
        -o Dir::Etc::main="$STAGE/etc/apt/apt.conf" \
        -o Dir::Etc::parts="$STAGE/etc/apt/apt.conf.d" \
        -o Dir::Etc::preferences="$STAGE/etc/apt/preferences" \
        -o Dir::Etc::preferencesparts="$STAGE/etc/apt/preferences.d" \
        -o Dir::State::lists="$STAGE/var/lib/apt/lists" \
        -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowDowngradeToInsecureRepositories=false \
        update
```

Trusted keyrings are **not** redirected — the staged run must verify against the
system's real keyrings, because that is the property being tested. Only after
this succeeds does activation copy files into the live tree, one atomic rename at
a time, in a deterministic order (new files first, then replacements, then
disables).

## Data produced by a run

```
$SDB_STATE_DIR/                      default: /var/lib/secure-debian-bootstrap
                                     (Termux: $PREFIX/var/lib/secure-debian-bootstrap)
  runs/<run-id>/
    run.log                          human-readable
    events.jsonl                     one JSON object per event
    detection.json                   platform + evidence + confidence
    inventory.tsv                    every config file, classified
    findings.jsonl                   audit findings
    plan.txt                         planned changes (also what --dry-run prints)
    applied.tsv                      changes actually made
    validation.txt                   staged-validation transcript
    report.txt / report.json         final summary
    staging/                         rendered configuration (kept on failure)
    stages/<stage>.done              resumability markers
  backups/<backup-id>/
    meta.json                        platform identity, run id, source roots
    manifest.sha256                  checksums of every archived file
    manifest.tsv                     path, type, mode, owner, group, mtime, link target
    files/                           the archived tree
  quarantine/<run-id>/
    manifest.tsv                     what was quarantined and why
    files/
```

`<run-id>` is `YYYYmmddTHHMMSSZ-<8 hex>`; `<backup-id>` is the same format and is
what `--rollback` takes.

## Extension points

Adding a platform requires exactly two things and no core edits:

1. `templates/<id>/` containing the repository files plus a `TEMPLATE.meta`
   recording `source`, `retrieved`, `confidence`, and `official_hosts`.
2. `lib/platforms/<id>.sh` defining:
   - `sdb_platform_<id>_roots` — where APT config lives
   - `sdb_platform_<id>_select_template` — which template file(s) to render
   - `sdb_platform_<id>_render_vars` — template substitutions
   - `sdb_platform_<id>_foreign_origins` — which other distributions' hosts are
     foreign here (MX, for instance, does not treat Debian as foreign)
   - `sdb_platform_<id>_hardening_profile` — which baseline controls apply

The launcher discovers platform modules by filename; detection maps `ID` to a
module name.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (audit clean, or requested changes applied and validated) |
| 1 | Generic failure |
| 2 | Usage error |
| 3 | Platform detection ambiguous or unsupported |
| 4 | Preflight failure (missing command, unwritable state dir, bad bash) |
| 5 | Backup missing or failed verification |
| 6 | Staged validation failed (nothing activated) |
| 7 | Refused: unsupported/EOL release |
| 8 | Refused: unsafe path or symlink |
| 9 | Refused: needs a decision but running `--non-interactive` |
| 10 | Rollback failure |
| 11 | Audit completed with high-severity findings (audit mode, `--strict`) |
| 12 | Lock held by another instance |
