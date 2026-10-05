# Security model

Keywall 0.1.4 is an accidental-disclosure guard, not a hostile-agent containment system. It has not received an independent security audit.

## Protected paths

- Password vault contents and metadata are authenticated and encrypted at rest with built-in .NET cryptography. On Windows, the first interactive unlock starts an in-memory session broker; subsequent commands in the same logon session reuse the derived key. The master password is not stored in a disk cache or environment variable.
- The broker's named pipes enforce CurrentUserOnly and are scoped by user SID, Windows session ID and canonical vault path. Vault salt must match; encrypted contents are authenticated and reloaded for every command. `kw lock` stops the broker; logout, restart, helper termination and software updates require a new unlock. Locking does not revoke a derived key already supplied to a running command. Closing the terminal or locking the desktop is not guaranteed to stop the broker.
- This is session convenience, not application authentication: any process running as the same Windows user in the same logon session can use the broker. `--no-session` bypasses caching for a single command; call `kw lock` first if an existing broker should be removed. Explicit password pipes bypass the cache and do not start it except for `login`/`unlock`. Other platforms require per-command unlock.
- Optional Windows DPAPI vaults bind to the Windows account, not to Keywall's process identity.
- Scans check registered secrets and a small, explicit set of common patterns locally. No validation request is sent to a key provider.
- `upload` scans a bounded memory snapshot and sends that exact snapshot over HTTPS to a stored target without redirects. It does not return secret headers or remote response bodies.
- `push` checks full reachable Git blobs, pins the inspected commit and expected destination ref, and rejects non-fast-forward updates. Git external helpers, hooks, credential managers and SSH settings remain part of the user's trusted environment.
- `run` masks known literal and common encoded secrets on stdout/stderr. It buffers a whole logical line and stops children emitting oversized lines. This is a convenience measure, not a sandbox.

## Limitations

The following are NOT prevented: direct network/file uploads, readable plaintext from other tools, malicious same-account/admin processes, stolen master passwords, tampered executable/configuration, secrets in screenshots, OCR, unknown encodings, transformations not enumerated by the scanner, provider formats not covered by rules, credentials already in remote history, process-memory capture, clipboard/terminal history, or malicious code passed to `run`.

Raw binary scanning does not imply semantic inspection of every binary format, packed executable or embedded encrypted payload. Known unsupported containers fail closed, but magic detection is not exhaustive. ZIP scanning does not extract files to disk. Limits and errors block the checked operation; callers must not interpret an error as success. Users can bypass wrappers and Git hooks.

Managed strings holding decrypted secrets/passwords cannot be reliably zeroized; temporary byte buffers and derived keys are zeroed where practical. Deleting a key is not secure disk erasure; copies and backups may persist. Crash dumps, paging and endpoint compromise remain risks. File permissions are inherited and not silently changed. Do not store the vault in publicly accessible folders. Interactive reveal deliberately prints a secret and therefore sacrifices output confidentiality.

Uploads only support PUT and do not enforce a public-IP-only destination policy. Targets are trusted user policy; using internal HTTPS services is allowed. Do not register attacker-controlled endpoints. In a threat model involving an Agent that may change policy, protect policy and execute the credential-holder under an isolated service account, enforce outbound permissions outside the Agent, and independently validate ordinary and elevated paths.

## Reporting

Do not put live keys or a decrypted vault in a public issue. Before public distribution, the repository owner should enable GitHub private vulnerability reporting. Report vulnerabilities privately through that channel once configured. In tests, use only disposable fixtures. Rotate any exposed key at its issuing service immediately; merely deleting a file or rewriting history does not revoke it.
