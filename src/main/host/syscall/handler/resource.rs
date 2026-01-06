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

    log_syscall!(
        munlock,
        /* rv */ std::ffi::c_int,
        /* addr */ *const std::ffi::c_void,
        /* len */ std::ffi::c_ulong,
    );
    pub fn munlock(
        _ctx: &mut SyscallContext,
        addr: ForeignPtr<()>,
        len: std::ffi::c_ulong,
    ) -> Result<(), SyscallError> {
        log::trace!("munlock called with addr={:?}, len={}", addr, len);

        // For simulation purposes, we'll just return success
        // In a real implementation, this would unlock the memory pages
        Ok(())
    }

    log_syscall!(
        munlockall,
        /* rv */ std::ffi::c_int,
    );
    pub fn munlockall(
        _ctx: &mut SyscallContext,
    ) -> Result<(), SyscallError> {
        log::trace!("munlockall called");

        // For simulation purposes, we'll just return success
        // In a real implementation, this would unlock all memory pages
        Ok(())
    }

    log_syscall!(
        msync,
        /* rv */ std::ffi::c_int,
        /* addr */ *const std::ffi::c_void,
        /* len */ std::ffi::c_ulong,
        /* flags */ std::ffi::c_int,
    );
    pub fn msync(
        _ctx: &mut SyscallContext,
        addr: ForeignPtr<()>,
        len: std::ffi::c_ulong,
        flags: std::ffi::c_int,
    ) -> Result<(), SyscallError> {
        log::trace!("msync called with addr={:?}, len={}, flags={}", addr, len, flags);

        // For simulation purposes, we'll just return success
        // In a real implementation, this would synchronize memory-mapped file
        Ok(())
    }

    log_syscall!(
        getresgid,
        /* rv */ std::ffi::c_int,
        /* rgid */ *mut linux_api::types::gid_t,
        /* egid */ *mut linux_api::types::gid_t,
        /* sgid */ *mut linux_api::types::gid_t
    );
    pub fn getresgid(
        ctx: &mut SyscallContext,
        rgid_ptr: ForeignPtr<linux_api::types::gid_t>,
        egid_ptr: ForeignPtr<linux_api::types::gid_t>,
        sgid_ptr: ForeignPtr<linux_api::types::gid_t>,
    ) -> Result<(), SyscallError> {
        // We don't need to check if the pointers are non-null since we don't
        // write to them if they are null.
        let mut rgid_ptr = rgid_ptr.clone();
        let mut egid_ptr = egid_ptr.clone();
        let mut sgid_ptr = sgid_ptr.clone();

        let (rgid, egid, sgid) = ctx.objs.process.getresgid()?;

        if !rgid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(rgid_ptr, &rgid)?;
        }
        if !egid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(egid_ptr, &egid)?;
        }
        if !sgid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(sgid_ptr, &sgid)?;
        }

        Ok(())
    }

    log_syscall!(
        getresuid,
        /* rv */ std::ffi::c_int,
        /* ruid */ *mut linux_api::types::uid_t,
        /* euid */ *mut linux_api::types::uid_t,
        /* suid */ *mut linux_api::types::uid_t
    );
    pub fn getresuid(
        ctx: &mut SyscallContext,
        ruid_ptr: ForeignPtr<linux_api::types::uid_t>,
        euid_ptr: ForeignPtr<linux_api::types::uid_t>,
        suid_ptr: ForeignPtr<linux_api::types::uid_t>,
    ) -> Result<(), SyscallError> {
        let (ruid, euid, suid) = ctx.objs.process.getresuid()?;

        if !ruid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(ruid_ptr, &ruid)?;
        }
        if !euid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(euid_ptr, &euid)?;
        }
        if !suid_ptr.is_null() {
            ctx.objs.process.memory_borrow_mut().write(suid_ptr, &suid)?;
        }

        Ok(())
    }

    log_syscall!(
        setresuid,
        /* rv */ std::ffi::c_int,
        /* ruid */ linux_api::types::uid_t,
        /* euid */ linux_api::types::uid_t,
        /* suid */ linux_api::types::uid_t
    );
    pub fn setresuid(
        _ctx: &mut SyscallContext,
        _ruid: linux_api::types::uid_t,
        _euid: linux_api::types::uid_t,
        _suid: linux_api::types::uid_t,
    ) -> Result<(), SyscallError> {
        // success always for now
        Ok(())
    }

    log_syscall!(
        setresgid,
        /* rv */ std::ffi::c_int,
        /* rgid */ linux_api::types::gid_t,
        /* egid */ linux_api::types::gid_t,
        /* sgid */ linux_api::types::gid_t
    );
    pub fn setresgid(
        _ctx: &mut SyscallContext,
        _rgid: linux_api::types::gid_t,
        _egid: linux_api::types::gid_t,
        _sgid: linux_api::types::gid_t,
    ) -> Result<(), SyscallError> {
        // success always for now
        Ok(())
    }
}
