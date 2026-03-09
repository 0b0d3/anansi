# Remove unwraps / add error handling

**Overview**
Several places assume successful parsing/indices/operations and use unwrap-like patterns (e.g., `.nth(1).unwrap_or("0")` usage and direct indexing into vectors) which can panic and crash the process.

**Where**
- `detect_debugger` parsing `/proc/self/status` lines
- Any code that indexes vectors without bounds checks (e.g., `self.superposition[0]` in `collapse`)

**Steps to reproduce**
- Trigger unexpected or malformed input (empty `status`, empty superposition) and observe process panic.

**Suggested fix**
- Replace indexing with safe access patterns (`get(0).cloned().ok_or(...)`) and propagate errors.
- Avoid panics in library code and return `Result` with meaningful error messages.

**Severity**: Medium
**Labels**: bug, robustness
