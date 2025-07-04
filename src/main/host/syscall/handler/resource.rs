use linux_api::errno::Errno;
use shadow_shim_helper_rs::syscall_types::ForeignPtr;

use crate::host::syscall::handler::{SyscallContext, SyscallHandler};
use crate::host::syscall::types::SyscallError;

impl SyscallHandler {
    log_syscall!(
        prlimit64,
        /* rv */ std::ffi::c_int,
        /* pid */ linux_api::posix_types::kernel_pid_t,
        /* resource */ std::ffi::c_uint,
        /* new_rlim */ *const std::ffi::c_void,
        /* old_rlim */ *const std::ffi::c_void,
    );
    pub fn prlimit64(
        _ctx: &mut SyscallContext,
        pid: linux_api::posix_types::kernel_pid_t,
        resource: std::ffi::c_uint,
        _new_rlim: ForeignPtr<()>,
        _old_rlim: ForeignPtr<()>,
    ) -> Result<(), SyscallError> {
        log::trace!("prlimit64 called on pid {pid} for resource {resource}");

        // TODO: For determinism, we may want to enforce static limits for certain resources, like
        // RLIMIT_NOFILE. Some applications like Tor will change behavior depending on these limits.

        if pid == 0 {
            // process is calling prlimit on itself
            Err(SyscallError::Native)
        } else {
            // TODO: We do not currently support adjusting other processes limits. To support it, we
            // just need to find the native pid associated with pid, and call prlimit on the native
            // pid instead.
            Err(Errno::EOPNOTSUPP.into())
        }
    }

    log_syscall!(
        setpriority,
        /* rv */ std::ffi::c_int,
        /* which */ std::ffi::c_int,
        /* who */ std::ffi::c_int,
        /* prio */ std::ffi::c_int,
    );
    pub fn setpriority(
        _ctx: &mut SyscallContext,
        which: std::ffi::c_int,
        who: std::ffi::c_int,
        prio: std::ffi::c_int,
    ) -> Result<(), SyscallError> {
        log::trace!("setpriority called with which={}, who={}, prio={}", which, who, prio);
        
        // For simulation purposes, we'll just return success
        // In a real implementation, this would set the process/thread priority
        Ok(())
    }

    log_syscall!(
        mlock,
        /* rv */ std::ffi::c_int,
        /* addr */ *const std::ffi::c_void,
        /* len */ std::ffi::c_ulong,
    );
    pub fn mlock(
        _ctx: &mut SyscallContext,
        addr: ForeignPtr<()>,
        len: std::ffi::c_ulong,
    ) -> Result<(), SyscallError> {
        log::trace!("mlock called with addr={:?}, len={}", addr, len);
        
        // For simulation purposes, we'll just return success
        // In a real implementation, this would lock the memory pages
        Ok(())
    }

    log_syscall!(
        mlockall,
        /* rv */ std::ffi::c_int,
        /* flags */ std::ffi::c_int,
    );
    pub fn mlockall(
        _ctx: &mut SyscallContext,
        flags: std::ffi::c_int,
    ) -> Result<(), SyscallError> {
        log::trace!("mlockall called with flags={}", flags);
        
        // For simulation purposes, we'll just return success
        // In a real implementation, this would lock all memory pages
        Ok(())
    }

    log_syscall!(
        mlock2,
        /* rv */ std::ffi::c_int,
        /* addr */ *const std::ffi::c_void,
        /* len */ std::ffi::c_ulong,
        /* flags */ std::ffi::c_int,
    );
    pub fn mlock2(
        _ctx: &mut SyscallContext,
        addr: ForeignPtr<()>,
        len: std::ffi::c_ulong,
        flags: std::ffi::c_int,
    ) -> Result<(), SyscallError> {
        log::trace!("mlock2 called with addr={:?}, len={}, flags={}", addr, len, flags);
        
        // For simulation purposes, we'll just return success
        // In a real implementation, this would lock the memory pages with flags
        Ok(())
    }
}
