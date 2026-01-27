const MAX_RUN_COMMAND_BUFFER = 2048

struct run_command_result
    ret_code::Cint
    std_out::Union{ByteString, Nothing}  # nullable
    std_err::Union{ByteString, Nothing}  # nullable
end

struct run_command_options{S <: AbstractString}
    command::S
end

function run_command_result_init(result::Base.RefValue)
    result[] = run_command_result(Cint(0), nothing, nothing)
    return OP_SUCCESS
end

function run_command_result_cleanup(result::Base.RefValue{run_command_result})
    string_destroy_secure(result[].std_out)
    string_destroy_secure(result[].std_err)
    return nothing
end

function run_command(options::run_command_options, result::Base.RefValue)
    result_buffer = Ref{ByteBuffer}()
    if byte_buf_init(result_buffer, MAX_RUN_COMMAND_BUFFER) != OP_SUCCESS
        return OP_ERR
    end

    command_ptr = Base.cconvert(Cstring, options.command)
    mode_ptr = Base.cconvert(Cstring, "r")
    stream = Ptr{Cvoid}(C_NULL)
    GC.@preserve command_ptr mode_ptr begin
        cmd = Base.unsafe_convert(Ptr{UInt8}, command_ptr)
        mode = Base.unsafe_convert(Ptr{UInt8}, mode_ptr)
        @static if _PLATFORM_WINDOWS
            stream = ccall((:_popen, "msvcrt"), Ptr{Cvoid}, (Ptr{UInt8}, Ptr{UInt8}), cmd, mode)
        else
            stream = ccall(:popen, Ptr{Cvoid}, (Ptr{UInt8}, Ptr{UInt8}), cmd, mode)
        end
    end

    ret_code = Cint(0)
    if stream != C_NULL
        output_buffer = Memory{UInt8}(undef, MAX_RUN_COMMAND_BUFFER)
        GC.@preserve output_buffer begin
            while ccall(:feof, Cint, (Ptr{Cvoid},), stream) == 0
                if ccall(
                        :fgets,
                        Ptr{UInt8},
                        (Ptr{UInt8}, Cint, Ptr{Cvoid}),
                        pointer(output_buffer),
                        Cint(MAX_RUN_COMMAND_BUFFER),
                        stream,
                    ) != C_NULL
                    cursor = byte_cursor_from_c_str(pointer(output_buffer))
                    if byte_buf_append_dynamic(result_buffer, cursor) != OP_SUCCESS
                        byte_buf_clean_up_secure(result_buffer)
                        return OP_ERR
                    end
                end
            end
        end
        @static if _PLATFORM_WINDOWS
            ret_code = ccall((:_pclose, "msvcrt"), Cint, (Ptr{Cvoid},), stream)
        else
            ret_code = ccall(:pclose, Cint, (Ptr{Cvoid},), stream)
        end
    end

    std_out = nothing
    trim_cursor = byte_cursor_from_buf(result_buffer)
    trimmed = byte_cursor_trim_pred(trim_cursor, char_is_space)
    if trimmed.len > 0
        std_out = string_new_from_array(Ptr{UInt8}(pointer(trimmed.ptr)), trimmed.len)
        std_out === nothing && return OP_ERR
    end

    result[] = run_command_result(ret_code, std_out, nothing)
    byte_buf_clean_up_secure(result_buffer)
    return OP_SUCCESS
end

function run_command(options::Base.RefValue{<:run_command_options}, result::Base.RefValue)
    return run_command(options[], result)
end
