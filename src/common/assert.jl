function fatal_assert(cond_str::AbstractString, file::AbstractString, line::Integer)
    write(Base.stderr, "FATAL_ASSERT: " * cond_str * " at " * file * ":" * string(line) * "\n")
    throw(ErrorException("FATAL_ASSERT: " * cond_str))
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
