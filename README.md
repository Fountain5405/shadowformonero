# shadowformonero

> **This is a fork of [shadow/shadow](https://github.com/shadow/shadow)
> maintained for [monerosim](https://github.com/Fountain5405/monerosim).**
> It carries patches that upstream Shadow does not (yet) include, needed
> to run real `monerod` and `monero-wallet-rpc` binaries inside Shadow's
> simulated network with deterministic behavior. Most users should be
> arriving here via `monerosim`'s `setup.sh`, which clones a pinned tag
> (currently `v0.1.0`); that's the supported entry point. The rest of
> the README below is upstream Shadow's own README, unmodified.
>
> - **Branched from upstream Shadow at commit:** `d24c0e587` (2025-07-02)
> - **Monerosim-fork tag tracking:** the fork is tagged in lock-step
>   with monerosim releases (`v0.1.0`, future `v0.2.0`, …). Use the tag
>   matching your monerosim version. `main` is the development branch.
> - **What this fork changes:** ~18 patches across DNS, sockets, locked
>   memory, missing syscalls, and RNG-construction-order — see
>   [`CHANGELOG-monerosim-fork.md`](CHANGELOG-monerosim-fork.md) for the
>   itemized list with rationale.
> - **Upstreaming:** the non-Monero-specific fixes (DNSSEC flag,
>   `sendmmsg` syscall handler, `SO_REUSEADDR`, `TCP_NODELAY` disable,
>   etc.) are candidates for upstream submission; the Monero-specific
>   bits (mlock-family for `monerod`'s secret-key pages, constructor
>   priority for the deterministic RNG interposer) are fork-only.
> - **Report monerosim-related issues** at the
>   [monerosim issue tracker](https://github.com/Fountain5405/monerosim/issues),
>   not the upstream Shadow tracker. Issues unrelated to the patches in
>   this fork should go to [shadow/shadow](https://github.com/shadow/shadow).

---

# The Shadow Simulator

## Quickstart

After installing the [dependencies](https://shadow.github.io/docs/guide/install_dependencies.html): build, test, and install Shadow into `~/.local`:

```
$ ./setup build --clean --test
$ ./setup test
$ ./setup install
```

Read the [usage guide](https://shadow.github.io/docs/guide) or get started with some [example simulations](https://shadow.github.io/docs/guide/getting_started_basic.html).

<!--- ANCHOR: body (for mdbook) -->

## What is Shadow?

Shadow is a discrete-event network simulator that directly executes real
application code, enabling you to simulate distributed systems with thousands of
network-connected processes in **realistic** and **scalable** private network
experiments using your laptop, desktop, or server running Linux.

Shadow experiments can be scientifically **controlled** and deterministically
**replicated**, making it easier for you to reproduce bugs and eliminate
confounding factors in your experiments.

## How Does Shadow Work?

Shadow directly executes **real applications**:

- Shadow directly executes unmodified, real application code using native OS
  (Linux) processes.
- Shadow co-opts the native processes into a discrete-event simulation by
  interposing at the system call API.
- The necessary system calls are emulated such that the applications need not
  be aware that they are running in a Shadow simulation.

Shadow connects the applications in a **simulated network**:

- Shadow constructs a private, virtual network through which the managed
  processes can communicate.
- Shadow internally implements simulated versions of common network protocols
  (e.g., TCP and UDP).
- Shadow internally models network routing characteristics (e.g., path latency
  and packet loss) using a configurable network graph.

## Why is Shadow Needed?

Network emulators (e.g., [mininet](http://mininet.org)) run real application
code on top of real OS kernels in real time, but are non-determinsitic and have
limited scalability: time distortion can occur if emulated processes exceed an
unknown computational threshold, leading to undefined behavior.

Network simulators (e.g., [ns-3](https://www.nsnam.org)) offer more experimental
control and scalability, but have limited application-layer realism because they
run application abstractions in place of real application code.

Shadow offers a novel, hybrid emulation/simulation architecture: it directly
executes real applications as native OS processes in order to faithfully
reproduce application-layer behavior while also co-opting the processes into a
high-performance network simulation that can scale to large distributed systems
with hundreds of thousands of processes.

## Caveats

Shadow implements **over 150 functions from the system call API**, but does not
yet fully support all API features. Although applications that make _basic_ use
of the supported system calls should work out of the box, those that use more
_complex_ features or functions may not yet function correctly when running in
Shadow. Extending support for the API is a work-in-progress.

That being said, we are particularly motivated to run large-scale [Tor
Network](https://www.torproject.org) simulations. This use-case is already
fairly well-supported and we are eager to continue extending support for it.

## More Information

Homepage:
- <https://shadow.github.io>

Documentation:
- [User documentation](https://shadow.github.io/docs/guide)
- [Developer documentation](https://shadow.github.io/docs/rust)

Community Support:
- <https://github.com/shadow/shadow/discussions>

Bug Reports:
- <https://github.com/shadow/shadow/issues>

<!--- ANCHOR_END: body (for mdbook) -->
