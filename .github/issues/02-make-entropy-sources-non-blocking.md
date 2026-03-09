# Make entropy sources non-blocking

**Overview**
`SystemEntropySource::collect` opens `/dev/urandom` and calls `read_exact` inside an async future. Although the caller wraps each source with `tokio::time::timeout`, the blocking read still blocks the executing thread and can stall the runtime.

**Where**
- `EntropyPool::new` instantiates `SystemEntropySource`
- `SystemEntropySource::collect` performs blocking file I/O

**Steps to reproduce**
1. Call `EntropyPool::harvest` from an async task on a runtime with limited worker threads.
2. Observe other tasks being delayed while the blocking read runs.

**Suggested fix**
- Use `getrandom`/`rand::rngs::OsRng` or `getrandom` crate which uses the OS RNG without blocking threads.
- Or run blocking reads inside `tokio::task::spawn_blocking`.
- Add a retry/timeout/fallback when entropy sources are slow.

**Severity**: High
**Labels**: bug, security, blocking-io
