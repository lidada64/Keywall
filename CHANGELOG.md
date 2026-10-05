# Changelog

## 0.1.5 — 2026-10-05

- Fix Git hook session access on Windows CI: .NET CurrentUserOnly compares TokenOwner, which can differ between processes running as the same user.
- Create named pipes with a protected DACL granting only the actual TokenUser SID access; validate client/server process user and Windows session before exchanging key material. Remote pipe clients are rejected.
- Keep the hook-smoke login-state assertion and remove temporary CI diagnostics. No password or key is written to disk or logs.

## 0.1.4 — 2026-10-05

- Fix clean pushes being blocked by secret blobs already reachable from the remote branch: both push and pre-push now inspect outgoing objects relative to the advertised remote ref.
- Ignored untracked .env files stay outside Git checks; secrets in unpushed history still block even after deleting or ignoring their paths.
- Missing advertised remote objects fail closed with instructions to fetch; new remote refs still inspect full reachable history.

## 0.1.3 — 2026-10-03

- Added per-repository `hook install|status|remove` to guard ordinary `git push`.
- Added `--global` to guard existing and future repositories that inherit global hooksPath, forwarding prior Git hooks and restoring configuration on removal.
- Existing pre-push hooks are preserved, chained with identical ref input, and restored on removal.
- Locked vaults block pushes with instructions to log in; custom hooksPath and modified managed hooks are not overwritten.

## 0.1.2 — 2026-10-03

- Windows in-memory unlock sessions: one master-password entry, then reuse across CLI commands.
- Added `login`/`unlock`, `lock`/`logout`, `status`, and per-command `--no-session`.
- Named pipes limit broker access to the current Windows user and logon session; no disk password cache.
- `kw add --help` and `kw help add` describe arguments without requiring a vault or password.
- Installer stops this installation's background session helpers before updating executable files.

## 0.1.1 — 2026-10-03

- Minimum master password length is now eight Unicode characters; existing vaults stay compatible.
- Windows packages and local installation include `kw.exe` as an equivalent shorthand sharing the default vault.
- Regression checks cover the seven/eight-character boundary and supplementary Unicode characters.

## 0.1.0 — 2026-10-03

- Independent local CLI with searchable encrypted aliases and metadata.
- Password-protected AES-GCM vault and optional Windows-user DPAPI mode.
- Hidden input, encrypted backup, atomic save and concurrent-writer guard.
- Scoped child-process environment injection with stdout/stderr masking.
- Registered-key and common-pattern scanning, including binary exact matches and nested ZIPs.
- Git history checks with immutable commit/destination-ref pinning.
- Stored HTTPS PUT targets and inspected-snapshot uploads without redirects.
- Bounded inputs and fail-closed scan errors; unsupported-container and Git LFS detection.
- Self-contained Windows x64 packaging, runtime licenses, hashes and CI/release workflows.

No universal network interception, clipboard copying, generic API proxy, persistent unlock agent or independent security audit in this release.
