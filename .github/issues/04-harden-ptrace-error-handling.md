# Harden ptrace error handling

**Overview**
`detect_debugger` calls `libc::ptrace(PTRACE_TRACEME, ...)` and treats a return value of -1 as "already traced" without checking `errno`. It also calls `PTRACE_DETACH` unconditionally which can be incorrect if `PTRACE_TRACEME` failed for other reasons.

**Where**
- `detect_debugger` in `src/core.rs`

**Steps to reproduce**
- Run under conditions where `ptrace` is restricted (e.g., seccomp, restricted container) and observe incorrect detection or unexpected side effects.

**Suggested fix**
- After `ptrace` returns `-1`, check `errno` to determine the cause (e.g., `EPERM` vs `ESRCH`) to correctly interpret "already traced".
- Only call `PTRACE_DETACH` if the earlier attach succeeded, and handle errors gracefully.
- Consider using safer detection alternatives where available.

**Severity**: Medium
**Labels**: bug, safety
