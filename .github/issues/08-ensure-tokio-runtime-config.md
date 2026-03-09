# Ensure Tokio runtime config

**Overview**
The code performs potentially-blocking operations from async contexts. If the binary runs on a single-threaded Tokio runtime, these operations will stall the reactor. The project should document runtime requirements or make code safe for single-threaded runtimes.

**Where**
- Any async function that currently performs blocking work (see other issues)

**Steps to reproduce**
- Run the application with a single-threaded runtime and exercise paths that perform blocking I/O.

**Suggested fix**
- Document the runtime requirement in `README.md` or ensure code uses `spawn_blocking` for all blocking operations.
- Add a runtime sanity check at startup and emit a warning if configured single-threaded.

**Severity**: Medium
**Labels**: docs, enhancement
