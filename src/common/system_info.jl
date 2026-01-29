struct cpu_info
    cpu_id::UInt16
    suspected_hyper_thread::Bool
end

function get_cpu_count_for_group(group_id::Integer)::Int
    return group_id == 0 ? Sys.CPU_THREADS : 0
end

function get_cpu_ids_for_group(group_id::Integer, dest::AbstractVector{cpu_info}, capacity::Integer)::Int
    if group_id != 0
        return 0
    end
    count = min(length(dest), capacity, Sys.CPU_THREADS)
    for i in 1:count
        dest[i] = cpu_info(UInt16(i - 1), false)
    end
    return count
end
