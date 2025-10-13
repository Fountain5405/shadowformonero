/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "lib/logger/logger.h"
#include "lib/shadow-shim-helper-rs/shim_helper.h"
#include "lib/shim/shim.h"
#include "lib/shim/shim_api.h"
#include "lib/shim/shim_sys.h"

// Startup message for shadowformonero version
static void shadowformonero_startup_message() {
    // Get current git commit hash
    const char* git_commit = "unknown";
#ifdef GIT_COMMIT_HASH
    git_commit = GIT_COMMIT_HASH;
#endif
    
    // Log startup message
    info("running shadowformonero at commit %s", git_commit);
    info("fast-path localhost RPC optimization enabled");
}

// Syscall numbers for socket operations
#define SYS_SOCKET 41
#define SYS_CONNECT 42

// Helper function to check if an address is localhost
static bool is_localhost_addr(const struct sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }
    
    switch (addr->sa_family) {
        case AF_INET: {
            const struct sockaddr_in* in_addr = (const struct sockaddr_in*)addr;
            uint32_t ip = ntohl(in_addr->sin_addr.s_addr);
            // Check for 127.0.0.0/8 (localhost range)
            return (ip & 0xFF000000) == 0x7F000000;
        }
        case AF_INET6: {
            const struct sockaddr_in6* in6_addr = (const struct sockaddr_in6*)addr;
            // Check for ::1 (IPv6 localhost)
            return memcmp(&in6_addr->sin6_addr, &in6_addr->sin6_addr, 16) == 0 &&
                   in6_addr->sin6_addr.s6_addr[15] == 1;
        }
        default:
            return false;
    }
}

// Helper function to handle localhost fast-path for socket operations
static bool handle_localhost_fastpath(long syscall_num, va_list args, long* rv) {
    trace("Handling localhost fast-path for syscall %ld", syscall_num);
    
    switch (syscall_num) {
        case SYS_SOCKET: {
            int domain = va_arg(args, int);
            int type = va_arg(args, int);
            int protocol = va_arg(args, int);
            
            trace("Fast-path socket creation: domain=%d, type=%d, protocol=%d", domain, type, protocol);
            
            // Create socket directly without Shadow network simulation
            int fd = socket(domain, type, protocol);
            if (fd < 0) {
                *rv = -1;
                return true;
            }
            
            trace("Fast-path socket created successfully: fd=%d", fd);
            *rv = fd;
            return true;
        }
        
        case SYS_CONNECT: {
            int sockfd = va_arg(args, int);
            const struct sockaddr* addr = va_arg(args, const struct sockaddr*);
            socklen_t addrlen = va_arg(args, socklen_t);
            
            trace("Fast-path connect: sockfd=%d, addrlen=%d", sockfd, addrlen);
            
            // Connect directly without Shadow network simulation
            int result = connect(sockfd, addr, addrlen);
            *rv = result;
            return true;
        }
        
        default:
            return false;
    }
}

static CEmulatedTime _shim_sys_get_time() {
    const ShimShmemHost* mem = shim_hostSharedMem();

    // If that's unavailable, fail. This shouldn't happen.
    if (mem == NULL) {
        panic("mem uninitialized");
    }

    return shimshmem_getEmulatedTime(mem);
}

uint64_t shim_sys_get_simtime_nanos() {
    // Call startup message on first invocation
    static bool startup_called = false;
    if (!startup_called) {
        shadowformonero_startup_message();
        startup_called = true;
    }
    
    return emutime_sub_emutime(_shim_sys_get_time(), EMUTIME_SIMULATION_START) /
           SIMTIME_ONE_NANOSECOND;
}

static CSimulationTime _shim_sys_latency_for_syscall(long n) {
    switch (n) {
        case SYS_clock_gettime:
        case SYS_time:
        case SYS_gettimeofday:
        case SYS_getcpu:
            // This would typically be a VDSO call outside of Shadow.
            //
            // It might not be, if the caller directly used a `syscall`
            // instruction or function call, but this is unusual, and charging
            // too-little latency here shouldn't hurt much, given that its main
            // purpose is currently to escape busy loops rather than to fully
            // model CPU time.
            return shimshmem_unblockedVdsoLatency(shim_hostSharedMem());
    }
    // This would typically *not* be a VDSO call outside of Shadow, even if
    // Shadow does implement it in the shim.
    return shimshmem_unblockedSyscallLatency(shim_hostSharedMem());
}

bool shim_sys_handle_syscall_locally(long syscall_num, long* rv, va_list args) {
    if (shim_getExecutionContext() != EXECUTION_CONTEXT_SHADOW) {
        panic("Unexpectedly called from non-shadow context");
    }
    // This function is called on every syscall operation so be careful not to doing
    // anything too expensive outside of the switch cases.

    char* syscallName = "<unknown>";

    // Fast-path localhost RPC optimization
    if (syscall_num == SYS_SOCKET || syscall_num == SYS_CONNECT) {
        // Extract address parameter for connect syscall
        const struct sockaddr* addr = NULL;
        if (syscall_num == SYS_CONNECT) {
            addr = va_arg(args, const struct sockaddr*);
        }
        
        if (addr == NULL || is_localhost_addr(addr)) {
            trace("Fast-path localhost bypass for syscall %ld", syscall_num);
            return handle_localhost_fastpath(syscall_num, args, rv);
        }
    }

    switch (syscall_num) {
        case SYS_clock_gettime: {
            syscallName = "clock_gettime";

            CEmulatedTime emulated_time = _shim_sys_get_time();

            trace("servicing syscall %ld:clock_gettime from the shim", syscall_num);

            clockid_t clk_id = va_arg(args, clockid_t);
            struct timespec* tp = va_arg(args, struct timespec*);

            if (clk_id < LINUX_CLOCK_REALTIME || clk_id > LINUX_CLOCK_TAI) {
                trace("found invalid clock id %ld", (long)clk_id);
                *rv = -EINVAL;
            } else if (tp) {
                *tp = (struct timespec){
                    .tv_sec = emulated_time / SIMTIME_ONE_SECOND,
                    .tv_nsec = emulated_time % SIMTIME_ONE_SECOND,
                };
                trace("clock_gettime() successfully copied time");
                *rv = 0;
            } else {
                trace("found NULL timespec pointer in clock_gettime");
                *rv = -EFAULT;
            }

            break;
        }

        case SYS_time: {
            syscallName = "time";

            CEmulatedTime emulated_time = _shim_sys_get_time();
            time_t now = emulated_time / SIMTIME_ONE_SECOND;

            trace("servicing syscall %ld:time from the shim", syscall_num);

            time_t* tp = va_arg(args, time_t*);

            if (tp) {
                *tp = now;
                trace("time() successfully copied time");
            }
            *rv = now;

            break;
        }

        case SYS_gettimeofday: {
            syscallName = "gettimeofday";

            CEmulatedTime emulated_time = _shim_sys_get_time();
            uint64_t micros = emulated_time / SIMTIME_ONE_MICROSECOND;

            trace("servicing syscall %ld:gettimeofday from the shim", syscall_num);

            struct timeval* tp = va_arg(args, struct timeval*);

            if (tp) {
                tp->tv_sec = micros / 1000000;
                tp->tv_usec = micros % 1000000;
                trace("gettimeofday() successfully copied time");
            }
            *rv = 0;

            break;
        }

        case SYS_sched_yield: {
            syscallName = "sched_yield";

            // Do nothing. We already yield and move time forward after some
            // number of unblocked syscalls.
            *rv = 0;

            break;
        }

        default: {
            // the syscall was not handled
            return false;
        }
    }

    int straceFd = shimshmem_getProcessStraceFd(shim_processSharedMem());

    if (straceFd >= 0) {
        // TODO: format the time
        uint64_t emulated_time_ms = shim_sys_get_simtime_nanos();
        pid_t tid = shimshmem_getThreadId(shim_threadSharedMem());

        char buf[100] = {0};
        int len = snprintf(buf, sizeof(buf), "%018ld [tid %d] %s(...) = %ld\n", emulated_time_ms,
                           tid, syscallName, *rv);
        len = MIN(len, sizeof(buf));

        int written = 0;
        while (1) {
            int write_rv = write(straceFd, buf + written, len - written);
            if (write_rv < 0) {
                if (errno == -EINTR || errno == -EAGAIN) {
                    continue;
                }
                warning("Unable to write to strace log");
                break;
            }
            written += write_rv;
            if (written == len) {
                break;
            }
        }
    }

    if (shimshmem_getModelUnblockedSyscallLatency(shim_hostSharedMem())) {
        ShimShmemHostLock* host_lock = shimshmemhost_lock(shim_hostSharedMem());
        shimshmem_incrementUnappliedCpuLatency(
            host_lock, _shim_sys_latency_for_syscall(syscall_num));
        CSimulationTime unappliedCpuLatency = shimshmem_getUnappliedCpuLatency(host_lock);
        // Count the syscall and check whether we ought to yield.
        CSimulationTime maxUnappliedCpuLatency =
            shimshmem_maxUnappliedCpuLatency(shim_hostSharedMem());
        trace("unappliedCpuLatency=%ld maxUnappliedCpuLatency=%ld", unappliedCpuLatency,
              maxUnappliedCpuLatency);
        if (unappliedCpuLatency > maxUnappliedCpuLatency) {
            // We still want to eventually return the syscall result we just
            // got, but first we yield control to Shadow so that it can move
            // time forward and reschedule this thread. This syscall itself is
            // a no-op, but the Shadow side will itself check and see that
            // unblockedCount > unblockedLimit, as it does before executing any
            // syscall.
            //
            // Since this is a Shadow syscall, it will always be passed through
            // to Shadow instead of being executed natively.

            CEmulatedTime newTime = _shim_sys_get_time() + unappliedCpuLatency;
            CEmulatedTime maxTime = shimshmem_getMaxRunaheadTime(host_lock);
            if (newTime <= maxTime) {
                shimshmem_setEmulatedTime(shim_hostSharedMem(), newTime);
                shimshmem_resetUnappliedCpuLatency(host_lock);
                shimshmemhost_unlock(shim_hostSharedMem(), &host_lock);
                trace("Reached maxUnappliedCpuLatency. Updated time locally. (%ld ns until max)",
                      maxTime - newTime);
            } else {
                shimshmemhost_unlock(shim_hostSharedMem(), &host_lock);
                trace("Reached maxUnappliedCpuLatency. Yielding. (%ld ns past max)",
                      newTime - maxTime);
                syscall(SHADOW_SYSCALL_NUM_SHADOW_YIELD);
            }
        } else {
            shimshmemhost_unlock(shim_hostSharedMem(), &host_lock);
        }
        // Should have been released and NULLed.
        assert(!host_lock);
    }

    // the syscall was handled
    return true;
}
