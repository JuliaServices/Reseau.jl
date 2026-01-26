struct memory_usage_stats
    maxrss::Csize_t
    page_faults::Csize_t
    _reserved::NTuple{8, Csize_t}
end

@static if !_PLATFORM_WINDOWS
    struct _rusage_timeval
        tv_sec::Clong
        tv_usec::Clong
    end

    struct _rusage
        ru_utime::_rusage_timeval
        ru_stime::_rusage_timeval
        ru_maxrss::Clong
        ru_ixrss::Clong
        ru_idrss::Clong
        ru_isrss::Clong
        ru_minflt::Clong
        ru_majflt::Clong
        ru_nswap::Clong
        ru_inblock::Clong
        ru_oublock::Clong
        ru_msgsnd::Clong
        ru_msgrcv::Clong
        ru_nsignals::Clong
        ru_nvcsw::Clong
        ru_nivcsw::Clong
    end
end

@static if _PLATFORM_WINDOWS
    struct _process_memory_counters
        cb::UInt32
        PageFaultCount::UInt32
        PeakWorkingSetSize::Csize_t
        WorkingSetSize::Csize_t
        QuotaPeakPagedPoolUsage::Csize_t
        QuotaPagedPoolUsage::Csize_t
        QuotaPeakNonPagedPoolUsage::Csize_t
        QuotaNonPagedPoolUsage::Csize_t
        PagefileUsage::Csize_t
        PeakPagefileUsage::Csize_t
    end
end

const _RUSAGE_SELF = 0

function init_memory_usage_for_current_process(stats::Ptr{memory_usage_stats})
    precondition(stats != C_NULL)
    zero_struct!(stats)
    @static if _PLATFORM_WINDOWS
        pmc = Ref{_process_memory_counters}()
        pmc[].cb = UInt32(sizeof(_process_memory_counters))
        handle = ccall((:GetCurrentProcess, "kernel32"), Ptr{Cvoid}, ())
        ok = ccall(
            (:GetProcessMemoryInfo, "psapi"),
            UInt8,
            (Ptr{Cvoid}, Ref{_process_memory_counters}, UInt32),
            handle,
            pmc,
            UInt32(sizeof(_process_memory_counters)),
        )
        ccall((:CloseHandle, "kernel32"), UInt8, (Ptr{Cvoid},), handle)
        if ok == 0
            return raise_error(ERROR_SYS_CALL_FAILURE)
        end
        unsafe_store!(
            stats,
            memory_usage_stats(
                Csize_t(pmc[].PeakWorkingSetSize),
                Csize_t(pmc[].PageFaultCount),
                ntuple(_ -> Csize_t(0), 8),
            ),
        )
        return OP_SUCCESS
    else
        usage = Ref{_rusage}()
        if ccall(:getrusage, Cint, (Cint, Ref{_rusage}), _RUSAGE_SELF, usage) != 0
            return raise_error(ERROR_SYS_CALL_FAILURE)
        end
        maxrss = Csize_t(usage[].ru_maxrss)
        @static if _PLATFORM_APPLE
            maxrss = maxrss ÷ 1024
        end
        unsafe_store!(
            stats,
            memory_usage_stats(maxrss, Csize_t(usage[].ru_majflt), ntuple(_ -> Csize_t(0), 8)),
        )
        return OP_SUCCESS
    end
end

function init_memory_usage_for_current_process(stats::Base.RefValue{memory_usage_stats})
    return init_memory_usage_for_current_process(Base.unsafe_convert(Ptr{memory_usage_stats}, stats))
end
