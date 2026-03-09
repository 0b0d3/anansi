# Platform checks for /proc usage

**Overview**
The code assumes Linux and reads `/proc/*` paths. On macOS and other non-Linux platforms these reads will fail repeatedly, causing noisy errors or repeated error handling logic.

**Where**
- `detect_debugger` (`/proc/self/status`)
- `detect_strace` (`/proc/self/cmdline`, `/proc/self/stat`)

**Steps to reproduce**
1. Run the binary on macOS.
2. Observe errors when code attempts to read `/proc` paths.

**Suggested fix**
- Guard Linux-specific code with `#[cfg(target_os = "linux")]` or runtime `cfg!(target_os = "linux")` checks.
- Provide alternative implementations for macOS (e.g., `sysctl` for process info) or gracefully skip those checks.

**Severity**: Medium
**Labels**: enhancement, portability
