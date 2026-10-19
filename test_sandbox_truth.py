import sys
import os
sys.path.insert(0, 'backend')
from app.execution.sandbox import SecureSandboxRunner

runner = SecureSandboxRunner(timeout_seconds=2.0)

print("--- SANDBOX ISOLATION SUITE ---")
# 1. Environment Sanitization
with runner as sb:
    code = 'import os; print("SANDBOX_ENV=" + os.environ.get("SUPPLYGRAPH_SANDBOX", "0")); print("HAS_AWS=" + str("AWS_SECRET_ACCESS_KEY" in os.environ))'
    res = sb.run([sys.executable, '-c', code])
    print(f"[TEST 1 Env Sanitization] mode={res.isolation_mode}, exit={res.exit_code}")
    print(f"Stdout:\n{res.stdout.strip()}")

# 2. Watchdog Timeout
with runner as sb:
    code = 'import time; time.sleep(5)'
    start = time.time() if 'time' in globals() else 0
    res = sb.run([sys.executable, '-c', code])
    print(f"\n[TEST 2 Watchdog Timeout] timed_out={res.timed_out}, exit={res.exit_code}, duration={res.duration_seconds}s")
    print(f"Violations: {res.security_violations}")

# 3. Path Traversal Zip-Slip Defense
with runner as sb:
    try:
        sb.write_file('../evil.txt', 'malicious payload')
        print("\n[TEST 3 Path Traversal] FAILED - Traversal was not blocked!")
    except ValueError as e:
        print(f"\n[TEST 3 Path Traversal] BLOCKED SUCCESS -> {e}")
