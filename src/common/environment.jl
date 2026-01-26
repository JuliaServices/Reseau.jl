function _env_name_ptr(name::ByteString)
    return string_c_str(name)
end

function _env_name_ptr(name::AbstractString)
    return Base.unsafe_convert(Ptr{UInt8}, Base.cconvert(Ptr{UInt8}, name))
end

function get_env(name::Ptr{UInt8})
    precondition(name != C_NULL)
    value = ccall(:getenv, Ptr{UInt8}, (Ptr{UInt8},), name)
    value == C_NULL && return nothing
    str = string_new_from_c_str(value)
    str === nothing && raise_error(ERROR_ENVIRONMENT_GET)
    return str
end

function get_env(name::AbstractString)
    name_ptr = Base.cconvert(Ptr{UInt8}, name)
    GC.@preserve name begin
        return get_env(Base.unsafe_convert(Ptr{UInt8}, name_ptr))
    end
end

function get_env_nonempty(name::Ptr{UInt8})
    precondition(name != C_NULL)
    value = ccall(:getenv, Ptr{UInt8}, (Ptr{UInt8},), name)
    if value == C_NULL || unsafe_load(value) == 0x00
        return nothing
    end
    str = string_new_from_c_str(value)
    str === nothing && raise_error(ERROR_ENVIRONMENT_GET)
    return str
end

function get_env_nonempty(name::AbstractString)
    name_ptr = Base.cconvert(Ptr{UInt8}, name)
    GC.@preserve name begin
        return get_env_nonempty(Base.unsafe_convert(Ptr{UInt8}, name_ptr))
    end
end

function get_environment_value(variable_name::Union{ByteString,AbstractString})
    name_ptr = _env_name_ptr(variable_name)
    value = ccall(:getenv, Ptr{UInt8}, (Ptr{UInt8},), name_ptr)
    value == C_NULL && return nothing
    str = string_new_from_c_str(value)
    str === nothing && raise_error(ERROR_ENVIRONMENT_GET)
    return str
end

function set_environment_value(
    variable_name::Union{ByteString,AbstractString},
    value::Union{ByteString,AbstractString},
)
    name_ptr = _env_name_ptr(variable_name)
    value_ptr = value isa ByteString ? string_c_str(value) : _env_name_ptr(value)
    @static if _PLATFORM_WINDOWS
        if ccall((:_putenv_s, "msvcrt"), Cint, (Ptr{UInt8}, Ptr{UInt8}), name_ptr, value_ptr) != 0
            return raise_error(ERROR_ENVIRONMENT_SET)
        end
    else
        if ccall(:setenv, Cint, (Ptr{UInt8}, Ptr{UInt8}, Cint), name_ptr, value_ptr, 1) != 0
            return raise_error(ERROR_ENVIRONMENT_SET)
        end
    end
    return OP_SUCCESS
end

function unset_environment_value(variable_name::Union{ByteString,AbstractString})
    name_ptr = _env_name_ptr(variable_name)
    @static if _PLATFORM_WINDOWS
        empty_ptr = Base.cconvert(Ptr{UInt8}, "")
        GC.@preserve empty_ptr begin
            if ccall((:_putenv_s, "msvcrt"), Cint, (Ptr{UInt8}, Ptr{UInt8}), name_ptr, empty_ptr) != 0
                return raise_error(ERROR_ENVIRONMENT_UNSET)
            end
        end
    else
        if ccall(:unsetenv, Cint, (Ptr{UInt8},), name_ptr) != 0
            return raise_error(ERROR_ENVIRONMENT_UNSET)
        end
    end
    return OP_SUCCESS
end
