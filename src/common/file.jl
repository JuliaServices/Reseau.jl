const FILE_TYPE_FILE = 1
const FILE_TYPE_SYM_LINK = 2
const FILE_TYPE_DIRECTORY = 4

const PATH_DELIM = _PLATFORM_WINDOWS ? UInt8('\\') : UInt8('/')
const PATH_DELIM_STR = _PLATFORM_WINDOWS ? "\\" : "/"

@inline function _c_str_is_empty(c_str::Ptr{UInt8})
    return c_str == C_NULL || unsafe_load(c_str) == 0x00
end

function byte_buf_init_from_file(out_buf::Base.RefValue{<:ByteBuffer}, filename::Ptr{UInt8})
    if _c_str_is_empty(filename)
        return raise_error(ERROR_FILE_INVALID_PATH)
    end
    name = unsafe_string(filename)
    return byte_buf_init_from_file(out_buf, name)
end

function byte_buf_init_from_file(out_buf::Base.RefValue{<:ByteBuffer}, filename::AbstractString)
    data = read(filename)
    if byte_buf_init(out_buf, length(data)) != OP_SUCCESS
        return OP_ERR
    end
    if !isempty(data)
        mem = out_buf[].mem
        GC.@preserve data mem begin
            Base.unsafe_copyto!(pointer(mem), pointer(data), length(data))
        end
        buf_val = out_buf[]
        out_buf[] = ByteBuffer(buf_val.mem, Csize_t(length(data)))
    end
    return OP_SUCCESS
end

function byte_buf_init_from_file_with_size_hint(
    out_buf::Base.RefValue{<:ByteBuffer},
    filename::Ptr{UInt8},
    _size_hint::Integer,
)
    return byte_buf_init_from_file(out_buf, filename)
end

function byte_buf_init_from_file_with_size_hint(
    out_buf::Base.RefValue{<:ByteBuffer},
    filename::AbstractString,
    _size_hint::Integer,
)
    return byte_buf_init_from_file(out_buf, filename)
end

function get_home_directory()
    home = homedir()
    return string_new_from_c_str(home)
end
