# Add timeouts for kernel calls

**Overview**
Calls to the `KernelInterface` (`create_false_breakpoints`, `inject_false_syscalls`, `cleanup`, etc.) are performed inline and may block or hang if the kernel driver misbehaves. These external calls can block the process or exhaust worker threads.

**Where**
- `activate_anti_debugging` (`kernel.create_false_breakpoints`)
- `inject_false_syscalls` (`kernel.inject_false_syscalls`)
- `shutdown` (`kernel.cleanup`)

**Steps to reproduce**
1. Load the module or driver in a state that causes long response time.
2. Trigger the code paths that call into `KernelInterface`.
3. Observe the calling task hang indefinitely.

**Suggested fix**
- Run kernel interactions inside `tokio::task::spawn_blocking`.
- Wrap calls with `tokio::time::timeout` and provide safe fallback behavior when timeouts occur.
- Add robust error reporting and retries with backoff if appropriate.

**Severity**: High
**Labels**: bug, blocking-io, kernel
