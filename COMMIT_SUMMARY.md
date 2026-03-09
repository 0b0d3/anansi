Commit summary for recent edits

This file records the files changed during the recent maintenance commit and a short description of the edits (for clarity and auditing).

Files modified

- src/core.rs
  - Converted several blocking I/O operations to async or offloaded them to `tokio::task::spawn_blocking`.
  - Made `detect_debugger` and `detect_strace` async; added platform guards to skip `/proc` on non-Linux.
  - Hardened `ptrace` handling (check errno, run in blocking thread).
  - Offloaded `/dev/urandom` reads to blocking task in `SystemEntropySource::collect`.
  - Made `RealityEngine::observe_file` async and offloaded file reads.
  - Replaced panic-prone `unwrap`/index usage with safe access/handling (e.g. `superposition.get(0)`).
  - Added two async tests to validate non-blocking behavior.
  - Adjusted PID file handling to be configurable and non-fatal.

- src/main.rs
  - Replaced `#[tokio::main]` with an explicit multi-threaded Tokio runtime builder.
  - Runtime worker count is configurable via `ANANSI_WORKER_THREADS`, defaults to `max(2, num_cpus::get())`.
  - Moved async main body to `async_main` and run via `rt.block_on`.

- Cargo.toml
  - Added `num_cpus` dependency to determine default worker count.

- .github/issues/*.md (9 files)
  - Added issue markdown files describing recommended fixes (blocking I/O, entropy sources, kernel timeouts, ptrace handling, platform checks, PID file, unwraps/error handling, runtime config, tests).

Notes about edited lines

- Many edits touch the `detect_debugger` and `detect_strace` functions: blocking file reads were replaced by `tokio::task::spawn_blocking(...)` and guarded with `cfg!(target_os = "linux")`.
- Kernel calls (`create_false_breakpoints`, `inject_false_syscalls`, `cleanup`) were moved into `spawn_blocking` with `tokio::time::timeout(2s)` wrappers.
- RNG `fill` calls were hardened with error handling (previous `unwrap()` removed) in `EntropyPool` methods.
- Tests added at the end of `src/core.rs` under `#[cfg(test)]` to assert that heartbeat tasks make progress while harvest/defense run.

If you want separate commits per-file instead of a single summary file, I can split these changes into multiple commits and push them (note: repository already has a commit with these edits).