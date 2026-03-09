# Offload blocking fs I/O

**Overview**
Several functions in `src/core.rs` perform blocking filesystem and I/O operations directly from async contexts (e.g., `std::fs::read_to_string`, `std::fs::File::open`, `std::fs::write`). On a Tokio runtime these calls can block reactor or worker threads and cause the process to appear frozen or unresponsive under load.

**Where**
- `detect_debugger` (reads `/proc/self/status`)
- `detect_strace` (reads `/proc/self/cmdline`, `/proc/self/stat`, parent cmdline)
- `RealityEngine::observe_file` (reads file contents)
- `new` (writes `/var/run/anansi.pid`)
- `SystemEntropySource::collect` (reads `/dev/urandom`) — related, but see separate issue for entropy sources

**Steps to reproduce**
1. Run the binary on a single-threaded Tokio runtime or with many concurrent tasks.
2. Trigger `defense_cycle` repeatedly or call APIs that hit the above functions concurrently.
3. Observe long pauses or stalled responsiveness.

**Suggested fix**
- Move all blocking filesystem and blocking I/O to `tokio::task::spawn_blocking` or use async-friendly crates (e.g., `tokio::fs`).
- Avoid blocking calls on hot paths; if necessary, cache results and poll less frequently.
- Add unit tests that exercise these paths under a multithreaded and single-threaded runtime to validate behavior.

**Severity**: High
**Labels**: bug, performance, blocking-io
