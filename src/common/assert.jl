function fatal_assert(cond_str::AbstractString, file::AbstractString, line::Integer)
    write(Base.stderr, "FATAL_ASSERT: " * cond_str * " at " * file * ":" * string(line) * "\n")
    throw(ErrorException("FATAL_ASSERT: " * cond_str))
end

function panic_oom(mem, msg::AbstractString)
    if mem == C_NULL || mem === nothing
        write(Base.stderr, msg * "\n")
        throw(OutOfMemoryError())
    end
    return nothing
end

function assume(cond::Bool)
    _ = cond
    return nothing
end

function unreachable()
    throw(ErrorException("UNREACHABLE"))
end

function debug_assert(cond::Bool)
    if DEBUG_BUILD[] && !cond
        fatal_assert("assertion failed", "<unknown>", 0)
    end
    return nothing
end

function fatal_assert_bool(cond::Bool, cond_str::AbstractString, file::AbstractString, line::Integer)
    if !cond
        fatal_assert(cond_str, file, line)
    end
    return nothing
end

function precondition(cond::Bool)
    debug_assert(cond)
    return nothing
end

function fatal_precondition(cond::Bool)
    if !cond
        fatal_assert("precondition failed", "<unknown>", 0)
    end
    return nothing
end

function postcondition(cond::Bool)
    debug_assert(cond)
    return nothing
end

function fatal_postcondition(cond::Bool)
    if !cond
        fatal_assert("postcondition failed", "<unknown>", 0)
    end
    return nothing
end
