# shadowformonero — fork changelog

Patches carried by this fork on top of upstream
[shadow/shadow](https://github.com/shadow/shadow). Organized by area
of the simulator they touch, not by chronological order. For the
strict commit log use `git log d24c0e587..main` against this repo.

**Branched from upstream Shadow at commit `d24c0e587` (2025-07-02).**

---

## v0.1.0 — 2026-05-12

Pinned to monerosim v0.1.0. `monerosim`'s `setup.sh` clones this
fork at the `v0.1.0` tag.

### Missing syscalls — `monerod` / `monero-wallet-rpc` need these

Real Monero binaries make syscalls that upstream Shadow either
stubs (returning ENOSYS) or doesn't handle at all. monerosim doesn't
modify the Monero source, so the simulator has to handle them.

- **`4f80c3acf`** Add missing syscalls for Monero compatibility:
  `mlock`, `mlockall`, `mlock2`, `setpriority`, `sendmmsg`.
  `monero{d,-wallet-rpc}` call `mlock` on pages holding secret keys to
  prevent swap-out; `setpriority` is used during startup.
- **`0dad56f75`** Implement missing syscalls for Monero simulation.
  Companion patch covering additional syscall surface.
- **`b2609ac1e`** Add `munlock`, `munlockall`, and `msync` syscall
  handlers. The other half of the `mlock` story — without `munlock`
  the locked-page bookkeeping isn't maintained correctly.
- **`0d15b8c8e`** Implement `sendmmsg` syscall handler instead of
  stub. Upstream had a stub returning ENOSYS; `monerod`'s P2P layer
  uses it for batched packet send.

### Sockets — `SO_REUSEADDR` / `TCP_NODELAY` / cleanup ordering

`monerod` exercises socket option corners that upstream Shadow's
TCP emulation doesn't always honor.

- **`2fb35adcc`** Add socket option handling for Monero compatibility.
- **`c9214c26b`** Implement proper `SO_REUSEADDR` socket option
  support.
- **`8c1aa305a`** Add lazy cleanup of closed sockets in
  `is_addr_in_use`.
- **`1bd031ce7`** Fix: always clean up closed sockets regardless of
  `reuseaddr` flag. Without this, ephemeral-port reuse fails for
  daemons that restart inside a sim (upgrade scenarios, late-joining
  miners, etc.).
- **`0ea98687d`** Fix `TCP_NODELAY` disable returning error in
  `legacy_tcp.rs`. `monerod` toggles `TCP_NODELAY` per connection.

### DNS interception

`monerod` uses libunbound for DNSSEC-validated seed-node and txt-
record lookups; Shadow's existing DNS resolver path didn't cover
that surface. Without these patches peer discovery silently fails.

- **`092cd52d7`** Add DNS query passthrough for `getaddrinfo()`.
- **`f8448f3c2`** Fix DNS peer discovery via LD_PRELOAD interposition
  of libunbound. The core of the DNS work — libunbound itself is
  intercepted so DNSSEC-validated lookups resolve against Shadow's
  in-memory DNS zone.
- **`404d301dd`** Set DNSSEC secure flag in libunbound interposer for
  DNS checkpoints. Round-trip flag setting so `monerod` accepts the
  responses as DNSSEC-validated.

### Determinism & RNG

- **`f52cfa1dd`** Set constructor priority 101 for deterministic RNG
  interception. Ensures the interposer that gives `monerod`'s libc
  RNG a deterministic seed is initialized before any consumer of
  random output. Without this, output order can vary across runs at
  the same `simulation_seed`.

### Signal handling and localhost fast-path

- **`a7949246f`** Remove fast-path localhost optimization and fix
  signal handling. The upstream fast-path bypassed Shadow's
  scheduler for 127.0.0.1 traffic, which broke `monerod`'s wallet-
  to-daemon RPC routing and produced signal-delivery races during
  daemon shutdown.

### Test / build hygiene (not behavior changes)

- **`16c950672`** Fix Rust type inference error in `test_unistd.rs`.

### Carry-overs from earlier exploration (WIP messages)

These three commits have informal messages but are part of the
production fork's current state. They will be reworded during the
v0.2.0 prep cycle so the public history reads better.

- **`94652c286`** "might be a memory bug, commiting so i can
  checkout main again"
- **`060750e48`** "local host bypass"
- **`4387075f e`** "local bypass for syscall shim thing"

---

## Upstreaming status

These commits are reasonable candidates for upstreaming to
shadow/shadow because they are not Monero-specific:

- `sendmmsg` syscall (`0d15b8c8e`)
- `SO_REUSEADDR` + closed-socket cleanup (`c9214c26b`, `8c1aa305a`,
  `1bd031ce7`)
- `TCP_NODELAY` disable fix (`0ea98687d`)
- `mlock`/`munlock` family — partial (some apps besides `monerod`
  use locked-memory hygiene for secrets)
- DNSSEC flag and libunbound interposition (`f8448f3c2`, `404d301dd`)
  — useful for any DNSSEC-validating application

The Monero-specific bits are fork-only by design:

- Constructor-priority hack for the deterministic RNG interposer
  (`f52cfa1dd`) — only matters for monerosim's specific testing
  workflow.
- Localhost fast-path removal (`a7949246f`) — disables an upstream
  optimization rather than fixing a bug. Should remain fork-only or
  be made opt-in via configuration if upstreamed.
