# Shadow for Monero

This is a fork of the [Shadow](https://shadow.github.io/) discrete-event network simulator, modified to support running Monero's `monerod` daemon and `monero-wallet-rpc` at scale (1000+ nodes).

Shadow executes real, unmodified application binaries and intercepts system calls via seccomp/LD_PRELOAD to route network I/O through a simulated network. Vanilla Shadow was built primarily for Tor simulations and lacks several features that Monero requires. This fork adds those features.

**Upstream fork point:** Shadow commit `d24c0e58` (July 2, 2025)
**Monero-specific changes:** 18 commits, ~2,400 lines added across 26 files

---

## Summary of Changes

| Category | Problem | Solution |
|----------|---------|----------|
| DNS / libunbound | Monero's DNS peer discovery and DNSSEC checkpoints fail silently | LD_PRELOAD interposition of the entire libunbound API |
| sendmmsg syscall | Vectorized send was a no-op stub, causing silent packet loss | Proper implementation iterating over message vectors |
| Socket options | Monero's setsockopt calls return ENOPROTOOPT, breaking connections | Graceful no-op handlers for IP_TOS, TCP_NODELAY, TCP_KEEP* |
| SO_REUSEADDR | Daemon phase switching can't rebind to the same address:port | Implement SO_REUSEADDR with lazy cleanup of CLOSED sockets |
| Memory syscalls | LMDB blockchain storage needs mlock/munlock/msync | No-op handlers (safe for simulation, avoids crashes) |
| RNG determinism | Monero's RNG initializes before Shadow's shim loads | Match constructor priority 101 so Shadow's shim wins the race |
| Signal handling | Process kill could panic instead of exiting | Use _exit() instead of unreachable!() after kill |

---

## Detailed Changes

### 1. DNS Resolution & libunbound Interposition

**The biggest problem.** Monero uses libunbound (not glibc) for two things:
- **Peer discovery** via DNS seed nodes (e.g., `seeds.moneroseeds.se`)
- **DNS checkpoints** via DNSSEC-signed TXT records that validate the blockchain at known heights

Libunbound creates internal TCP sockets that never call `connect()`. Shadow doesn't know how to handle unconnected sockets, causing 15-second timeouts and zero DNS results.

**Solution:** Instead of patching libunbound internals, intercept the entire libunbound C API via LD_PRELOAD (`unbound_interpose.c`, 667 lines):
- Intercepts `ub_ctx_create()`, `ub_ctx_config()`, `ub_resolve()`, `ub_resolve_free()`
- Constructs raw RFC 1035 DNS wire-format queries
- Sends UDP packets through Shadow's simulated network to a configured DNS server
- Parses responses and reconstructs the `ub_result` struct that Monero expects
- Sets `ub_result.secure = 1` so Monero's DNSSEC checkpoint validation passes

Also added a `getaddrinfo()` DNS fallback (`shim_api_addrinfo.c`) that queries an external DNS server when Shadow's internal hostname database has no answer.

**Commits:** `f8448f3c2`, `404d301dd`, `092cd52d7`

### 2. sendmmsg Syscall

Monero uses `sendmmsg()` (vectorized sendmsg) for P2P communication. The original Shadow handler was a stub that returned `vlen` without actually sending any data — silent packet loss.

**Fix:** Iterate over the message vector, read each `msghdr` from the process, call the existing `Socket::sendmsg()` for actual transmission, and write back `msg_len` with bytes sent. Caps `vlen` to `UIO_MAXIOV` (1024) per kernel semantics.

**Commit:** `0d15b8c8e`

### 3. Socket Options

Monero calls `setsockopt()` with options Shadow didn't recognize, causing ENOPROTOOPT errors:

| Option | Used by Monero for |
|--------|-------------------|
| `IP_TOS` | QoS network priority |
| `IP_BIND_ADDRESS_NO_PORT` | Port binding optimization |
| `TCP_NODELAY` | Nagle's algorithm control |
| `TCP_KEEPIDLE` | Idle time before keepalives |
| `TCP_KEEPINTVL` | Keepalive probe interval |

All are implemented as no-ops with trace logging. Shadow doesn't simulate these features, but returning success prevents connection failures.

**Commits:** `2fb35adcc`, `0ea98687d`

### 4. SO_REUSEADDR & Socket Cleanup

Monerosim uses daemon phases (e.g., upgrade from v1 to v2 at a specific block height). When a daemon process terminates and a new one starts, it needs to bind to the same IP:port. Without SO_REUSEADDR, the new process gets "Address already in use" because the old socket lingers in CLOSED state.

**Fix:** Implemented SO_REUSEADDR on TCP and UDP sockets. Added lazy cleanup of CLOSED sockets during address binding checks — when a new socket tries to bind and finds a CLOSED socket on that address, the dead socket is automatically cleaned up.

**Commits:** `c9214c26b`, `8c1aa305a`, `1bd031ce7`

### 5. Memory Locking & Sync Syscalls (LMDB)

Monero uses LMDB for blockchain storage, which calls memory locking and sync syscalls that Shadow didn't implement:

| Syscall | Purpose | Implementation |
|---------|---------|---------------|
| `mlock` / `mlock2` | Lock pages in memory | No-op (return success) |
| `mlockall` | Lock all pages | No-op |
| `munlock` / `munlockall` | Unlock pages | No-op |
| `msync` | Sync memory-mapped file | No-op |
| `setpriority` | Process priority | No-op |
| `setresuid` / `setresgid` | Credential management | Track in ProcessCred struct |
| `setfsuid` / `setfsgid` | Filesystem credentials | Track in ProcessCred struct |

No-ops are safe here because Shadow doesn't need actual memory locking for simulation correctness. Without these handlers, LMDB crashes with "Function not implemented".

**Commits:** `0dad56f75`, `b2609ac1e`, `4f80c3acf`

### 6. RNG Constructor Priority

Monero initializes its random number generator in a constructor function with GCC priority 101. If Shadow's shim loads after this, Monero reads real `/dev/urandom` data, breaking simulation determinism (non-reproducible block mining).

**Fix:** Set Shadow's injector constructor to priority 101. Since GCC reserves priorities 0-100 for the runtime, and matching-priority constructors execute in LD_PRELOAD order, Shadow's shim (first in LD_PRELOAD) wins the race and intercepts `/dev/urandom` before Monero's RNG init.

**Commit:** `f52cfa1dd`

### 7. Signal Handling

After sending SIGKILL to a managed process, Shadow called `unreachable!()` which panics. Monero processes don't always terminate immediately, so this caused spurious crashes.

**Fix:** Use `_exit()` for graceful termination instead of panicking.

**Commit:** `a7949246f`

---

## Files Changed (from upstream fork point)

```
src/lib/preload-libc/unbound_interpose.c    | 667 +++  (NEW - libunbound interposition)
src/lib/preload-libc/CMakeLists.txt          |   2 ~
src/lib/shim/shim_api_addrinfo.c             | 324 +++  (DNS fallback for getaddrinfo)
src/lib/shim/shim_sys.c                      |  33 +
src/lib/shim/src/signals.rs                  |   5 ~
src/main/core/configuration.rs               |   8 +
src/main/core/manager.rs                     |   3 +
src/main/host/descriptor/socket/inet/
    legacy_tcp.rs                             |  80 +++
    tcp.rs                                    |  56 +++
    udp.rs                                    |  33 +++
    mod.rs                                    |  13 ~
src/main/host/network/
    interface.rs                              |  33 +++
    namespace.rs                              |  13 ~
src/main/host/host.rs                        |   2 +
src/main/host/process.rs                     |  42 +++
src/main/host/syscall/formatter.rs           |  11 +
src/main/host/syscall/handler/
    mod.rs                                    |  57 +++
    resource.rs                               | 222 +++  (NEW - mlock/munlock/msync)
    socket.rs                                 | 108 +++
    unistd.rs                                 |  83 +++  (NEW - credential syscalls)
```

Total: ~2,400 lines added, ~100 lines modified across 26 files.

---

## Building

Same as upstream Shadow. From the repo root:

```bash
./setup build --prefix ~/.local
./setup install
```

Or via the monerosim `setup.sh` which handles this automatically.
