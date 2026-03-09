# Add tests for non-blocking behavior

**Overview**
There are no tests ensuring that hot-path operations (entropy harvest, observer detection, deception maintenance) do not block the async runtime. Adding tests will prevent regressions when refactoring blocking calls.

**Where**
- Test `EntropyPool::harvest`, `detect_observers`, `defense_cycle` concurrency behavior.

**Steps to reproduce**
- N/A (this is a test addition)

**Suggested fix**
- Add unit/integration tests that run these functions under both single-threaded and multi-threaded Tokio runtimes, asserting that other tasks make progress and timeouts behave correctly.
- Add CI checks to run these tests on PRs.

**Severity**: Low
**Labels**: test, ci
