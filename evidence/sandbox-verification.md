# SupplyGraph v3.5 — Behavioral Sandbox & Binary Inspection Verification

**Evaluation Date:** October 19, 2026  
**Auditor:** Principal AppSec Architect  
**Components Evaluated:** `backend/app/services/sandbox_runner.py`, `backend/app/services/binary_inspector.py`  

---

## 1. Sandbox Architecture & Isolation Controls

SupplyGraph provides an isolated execution harness for detonating untrusted package install scripts (e.g., npm `postinstall` hooks, Python `setup.py` scripts).

```
   Untrusted Package
          │
          ▼
┌────────────────────────────────────────┐
│  SupplyGraph Sandbox Controller        │
│  (sandbox_runner.py)                   │
└──────────────────┬─────────────────────┘
                   │
      ┌────────────┴────────────┐
      ▼                         ▼
[Primary: Docker]        [Fallback: Subprocess]
--network none           Watchdog timer (10s)
--memory=512m            Memory limit
--cpus=1.0               Process tree termination
10s execution cap        Isolated temp workspace
Default seccomp profile
```

### 1.1 Docker Container Isolation Parameters
When Docker runtime is active, execution is launched with strictly constrained flags:
- **Zero Network Egress:** `--network none`  
  Prevents all outbound network connections, blocking reverse shells, HTTP beaconing, DNS exfiltration, and C2 payload downloading.
- **Memory Ceiling:** `--memory=512m`  
  Guards host against memory-exhaustion Denial-of-Service attacks (e.g., fork bombs or memory-leak loops).
- **CPU Ceiling:** `--cpus=1.0`  
  Limits CPU consumption to 1 core, preventing starvation of host services.
- **Execution Watchdog:** 10-second wall-clock timeout  
  Enforces process termination (`SIGKILL`) if execution does not complete within 10 seconds.
- **Syscall Filtering (Seccomp):** Default Docker Seccomp profile  
  Blocks ~44 dangerous system calls, including `ptrace`, `bpf`, `reboot`, `kexec_load`, and namespace manipulation calls.

### 1.2 Restricted Subprocess Fallback
In environments where the Docker daemon is absent or unprivileged (such as serverless container hosts or constrained CI environments), SupplyGraph falls back to a subprocess runner:
- Spawns process within a temporary, isolated working directory (`tempfile.mkdtemp`).
- Monitors execution with an asynchronous watchdog timer (10s cap).
- Recursively kills the child process tree via `psutil` upon timeout or exception.

---

## 2. Static Binary Inspector (PE, ELF, WASM)

In addition to dynamic script detonation, SupplyGraph implements static binary inspection in `backend/app/services/binary_inspector.py`:
- **Zero Host Execution:** The binary payload is never executed or mapped as runnable code on the host.
- **Static String & Pattern Extraction:**
  - Scans PE (`.exe`, `.dll`), ELF (`.elf`, `.so`), and WebAssembly (`.wasm`) binaries.
  - Identifies embedded C2 URLs, IP addresses, discord webhooks, and raw socket connection strings.
  - Parses import tables to detect suspicious API primitives: `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`, `ptrace`, `dlopen`, `system`, and `execve`.

---

## 3. Honest Security Disclosures & Defensible Boundaries

1. **No "Zero Host Risk" Claims:** SupplyGraph does not claim zero host risk. Kernel-level 0-day exploits or microarchitectural side-channel attacks can conceptually bypass containerization; our defense-in-depth model minimizes exposure through network isolation, resource limits, and non-root execution.
2. **Deterministic & Reproducible:** Unit tests in `backend/tests/unit/test_execution_sandbox.py` verify that timeouts correctly kill hanging scripts, exit codes are accurately captured, and stdout/stderr streams are securely truncated.
