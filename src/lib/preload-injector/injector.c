/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

#include <stddef.h>
#include <syscall.h>

#include "lib/shim/shim_api.h"

/// The purpose of the injector library is to facilitate connecting Shadow to
/// each of the managed processes that it runs. This interaction is controlled
/// using a shim. We have two main goals:
///
///   1. Inject the shim into the managaged process space.
///   2. Be minimally invasive, i.e., do not unnecessarily intercept functions
///      called by the managed process.
///
/// We accomplish the first goal by preloading the injector lib, which links to
/// the shim and calls a shim function in a constructor (to ensure that the shim
/// does get loaded). We accomplish the second goal by defining no other
/// functions in this injector lib, which decouples shim injection from function
/// interception.
///
/// Notes:
///
///   - We do not preload the shim directly because it does not meet the second
///   goal of being minimally invasive.
///   - Technically, the shim will already be injected if there are other
/// preloaded libraries that link to it. But the injector library enables a
/// minimally invasive way to inject the shim that works even if those other
/// libraries are not preloaded.

// A constructor is used to load the shim as soon as possible.
// Priority 101 is the lowest user-settable priority (GCC reserves 0-100).
// When multiple constructors have the same priority, LD_PRELOAD order determines
// execution order - libraries listed first in LD_PRELOAD run their constructors first.
// Monerod's init_random() uses priority 101, so using the same priority here
// combined with LD_PRELOAD ordering ensures Shadow's shim loads BEFORE monerod's
// RNG initialization, allowing Shadow to intercept /dev/urandom reads.
__attribute__((constructor(101), used)) void _injector_load() {
    // Make a call to the shim to ensure that it's loaded. The SYS_time syscall
    // will be handled locally in the shim, avoiding IPC with Shadow.
    shim_api_syscall(SYS_time, NULL);
    return;
}

// Do NOT define other symbols.
