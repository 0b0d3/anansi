# Avoid blocking PID file write

**Overview**
`new` writes `/var/run/anansi.pid` synchronously during initialization. This can block if the filesystem is slow or permissions cause delays. It may also fail on systems without `/var/run` or with restricted permissions.

**Where**
- `AnansiCore::new` — `std::fs::create_dir_all("/var/run")` and `std::fs::write("/var/run/anansi.pid", ...)`

**Steps to reproduce**
- Run init on a system with slow I/O or without write permission to `/var/run`.

**Suggested fix**
- Perform PID file creation inside `tokio::task::spawn_blocking` or defer to process supervisor.
- Make the path configurable and handle permission errors gracefully.

**Severity**: Low
**Labels**: bug, usability
