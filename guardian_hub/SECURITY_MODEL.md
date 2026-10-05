# Security model (Stages 1 and 2)

## Trust boundaries

```
 UI / CLI client            broker (root)                     worker (dedicated uid)
 any local uid  --socket--> identity: SO_PEERCRED   --pipes--> parses untrusted data
                            policy: uid -> capabilities          no privileges, limits,
                            validates everything                 NO_NEW_PRIVS, not dumpable
```

- **Client to broker.** The kernel supplies the client's uid, so a client
  cannot claim a different identity. Each uid maps to an explicit
  capability set. Root gets nothing implicitly. Unknown uids are refused
  before any request is read.
- **Broker to worker.** Workers are untrusted once they have read their
  input. Their output must be exactly one canonical frame within size and
  time limits from a process that exits 0. Anything else is a failure.
  Workers are never reused.
- **Configuration.** The policy file, the code tree and the interpreter must
  be owned by root and not writable by others when the broker runs as root.
  Workers never prepend their own directory to `sys.path`, so code next to
  the package cannot shadow the standard library.

## What is enforced today

- Default deny. An operation runs only if the principal holds its
  capability. Authorization happens before parameter validation, so an
  unauthorized client learns nothing from validation errors.
- Capabilities that touch keys, vaults, deployments or device contents need
  the `owner_key` factor. Nothing can grant that factor until Stage 5
  (YubiKey), so these operations are unreachable for now.
- Worker sandbox, set up and verified before any input is read:
  - setgroups/setresgid/setresuid to the worker account, with a check that
    root cannot be regained
  - RLIMIT_CORE 0, CPU and memory limits, an open-file limit, RLIMIT_FSIZE 0
    (no file writes), RLIMIT_NPROC 0 (no fork)
  - NO_NEW_PRIVS and non-dumpable, with umask 077, cwd `/`, a two-variable
    environment and no inherited descriptors
  - its own session, so the whole process group is killed on timeout
- The broker makes itself non-dumpable, which blocks same-uid ptrace and
  core dumps.
- Every frame on the socket and on worker pipes is canonical JSON, at most
  1 MiB, and read against a deadline. Duplicate keys, floats, BOMs, lone
  surrogates and excessive nesting are rejected.
- Errors cross boundaries only as a code plus a sanitized message.
  Tracebacks and internal exception text are never sent.
- Logs are JSON lines in ASCII. Secret-named fields are redacted, binary data
  is never logged, untrusted text is escaped, and files are 0600, opened with
  O_NOFOLLOW and rotated.

## Known limitations (not hidden, not yet fixed)

- **No syscall filter, Landlock or network isolation for workers yet** (see
  ROADMAP). A worker running as the dedicated account can still open
  sockets and read world-readable files.
- **Development mode** (broker not root): workers share the user's uid.
  RLIMIT_FSIZE stops them writing data, but they can still unlink, rename
  or chmod that user's files, and they can signal other processes of that
  uid. Use development mode only for development.
- **The worker account must be dedicated.** Processes with the same uid can
  signal each other. Do not reuse `nobody` in production, because other
  services run as it. The test suite uses 65534 only because it is always
  present.
- **Authorization by uid alone** means any process running as an authorized
  uid has that uid's capabilities. The `owner_key` factor (Stage 5) is meant
  to require physical presence for anything sensitive.
- The broker has no rate limiting beyond the connection and concurrent-worker
  caps.
