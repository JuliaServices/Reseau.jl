# AWS IO Library - Stream Abstractions
# Port of aws-c-io/source/stream.c and include/aws/io/stream.h

# Stream seek basis
@enumx StreamSeekBasis::UInt8 begin
    BEGIN = 0
    END = 2
end

# Stream status
@enumx StreamStatus::UInt8 begin
    OK = 0
    END_OF_STREAM = 1
    ERROR = 2
end

struct InputStreamStatus
    is_end_of_stream::Bool
    is_valid::Bool
end

# Abstract stream interface
abstract type AbstractInputStream end

import Base: readbytes!, eof

# Stream vtable interface methods

# Read from stream into buffer, returns (bytes_read, status)
function stream_read(stream::AbstractInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    error("stream_read must be implemented for $(typeof(stream))")
end

# Get stream status (valid + end-of-stream)
function stream_get_status(stream::AbstractInputStream)::Union{InputStreamStatus, ErrorResult}
    error("stream_get_status must be implemented for $(typeof(stream))")
end

# Seek to position in stream
function stream_seek(stream::AbstractInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    error("stream_seek must be implemented for $(typeof(stream))")
end

# Get current stream length
function stream_get_length(stream::AbstractInputStream)::Union{Int64, ErrorResult}
    error("stream_get_length must be implemented for $(typeof(stream))")
end

# Get current position in stream
function stream_get_position(stream::AbstractInputStream)::Union{Int64, ErrorResult}
    error("stream_get_position must be implemented for $(typeof(stream))")
end

# Destroy/cleanup stream
function stream_destroy!(stream::AbstractInputStream)::Nothing
    # Default: do nothing
    return nothing
end

function readbytes!(stream::AbstractInputStream, buf::Vector{UInt8}, nb::Int)
    nb <= 0 && return 0
    to_read = min(nb, length(buf))
    to_read == 0 && return 0
    byte_buf = byte_buf_from_empty_array(buf, to_read)
    result = stream_read(stream, byte_buf, to_read)
    if result isa ErrorResult
        raise_error(result.code)
        error("stream_read failed with error code $(result.code)")
    end
    read_len, _ = result
    return Int(read_len)
end

function eof(stream::AbstractInputStream)::Bool
    status = stream_get_status(stream)
    status isa ErrorResult && return true
    return status.is_end_of_stream
end

# Acquire/release hooks for API parity (no refcount in Julia)
function input_stream_acquire(stream::AbstractInputStream)
    return stream
end

function input_stream_release(stream::AbstractInputStream)
    stream_destroy!(stream)
    return nothing
end

input_stream_destroy(stream::AbstractInputStream) = input_stream_release(stream)

# Check if stream is seekable
function stream_is_seekable(stream::AbstractInputStream)::Bool
    return false
end

# Check if stream length is known
function stream_has_known_length(stream::AbstractInputStream)::Bool
    return true
end

# =============================================================================
# ByteBuffer Input Stream - reads from a ByteBuffer
# =============================================================================

mutable struct ByteBufferInputStream <: AbstractInputStream
    buffer::ByteBuffer
    position::Csize_t
    owns_buffer::Bool
end

function ByteBufferInputStream(buffer::ByteBuffer; owns_buffer::Bool = false)
    return ByteBufferInputStream(buffer, Csize_t(0), owns_buffer)
end

function ByteBufferInputStream(data::AbstractVector{UInt8}; owns_buffer::Bool = true)
    buf = ByteBuffer(length(data))
    if !isempty(data)
        copyto!(buf.mem, 1, data, 1, length(data))
        buf.len = Csize_t(length(data))
    end
    return ByteBufferInputStream(buf, Csize_t(0), owns_buffer)
end

function stream_read(stream::ByteBufferInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    tracing_task_begin(tracing_input_stream_read)
    try
        available = stream.buffer.len - stream.position
        space = buffer.capacity - buffer.len
        to_read = min(Csize_t(length), available, space)

        if to_read == 0
            return (Csize_t(0), available == 0 ? StreamStatus.END_OF_STREAM : StreamStatus.OK)
        end

        # Copy data
        src_start = Int(stream.position) + 1
        dst_start = Int(buffer.len) + 1
        copyto!(buffer.mem, dst_start, stream.buffer.mem, src_start, Int(to_read))
        buffer.len = buffer.len + to_read

        stream.position += to_read

        status = stream.position >= stream.buffer.len ? StreamStatus.END_OF_STREAM : StreamStatus.OK
        return (to_read, status)
    finally
        tracing_task_end(tracing_input_stream_read)
    end
end

function stream_seek(stream::ByteBufferInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    new_pos = if basis == StreamSeekBasis.BEGIN
        offset
    elseif basis == StreamSeekBasis.END
        Int64(stream.buffer.len) + offset
    else
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    if new_pos < 0 || new_pos > Int64(stream.buffer.len)
        raise_error(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
        return ErrorResult(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
    end

    stream.position = Csize_t(new_pos)
    return nothing
end

function stream_get_length(stream::ByteBufferInputStream)::Union{Int64, ErrorResult}
    return Int64(stream.buffer.len)
end

function stream_get_position(stream::ByteBufferInputStream)::Union{Int64, ErrorResult}
    return Int64(stream.position)
end

function stream_is_seekable(stream::ByteBufferInputStream)::Bool
    return true
end

function stream_has_known_length(stream::ByteBufferInputStream)::Bool
    return true
end

function stream_destroy!(stream::ByteBufferInputStream)::Nothing
    # Buffer cleanup handled by GC
    return nothing
end

function stream_get_status(stream::ByteBufferInputStream)::Union{InputStreamStatus, ErrorResult}
    is_end = stream.position >= stream.buffer.len
    return InputStreamStatus(is_end, true)
end

# =============================================================================
# File Input Stream - reads from a file
# =============================================================================

mutable struct FileInputStream <: AbstractInputStream
    file::Union{Libc.FILE, Nothing}
    close_on_cleanup::Bool
end

const _FILE_STREAM_READ_MODE = "rb"
const _FILE_STREAM_SEEK_SET = Cint(0)
const _FILE_STREAM_SEEK_END = Cint(2)

# Windows CRT doesn't provide POSIX `fseeko`/`ftello` symbols, and the 64-bit
# MSVC variants aren't always available in the CRT that Julia is linked against.
@static if Sys.iswindows()
    function _file_stream_seek(file::Libc.FILE, offset::Int64, whence::Cint)::Cint
        offset_long = Clong(offset)
        if Int64(offset_long) != offset
            Libc.errno(Libc.EINVAL)
            return Cint(-1)
        end
        return ccall(:fseek, Cint, (Ptr{Cvoid}, Clong, Cint), file.ptr, offset_long, whence)
    end

    function _file_stream_tell(file::Libc.FILE)::Int64
        return Int64(ccall(:ftell, Clong, (Ptr{Cvoid},), file.ptr))
    end
else
    function _file_stream_seek(file::Libc.FILE, offset::Int64, whence::Cint)::Cint
        return ccall(:fseeko, Cint, (Ptr{Cvoid}, Int64, Cint), file.ptr, offset, whence)
    end

    function _file_stream_tell(file::Libc.FILE)::Int64
        return ccall(:ftello, Int64, (Ptr{Cvoid},), file.ptr)
    end
end

function _file_open_read(path::AbstractString)::Union{Libc.FILE, ErrorResult}
    file_ptr = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path, _FILE_STREAM_READ_MODE)
    if file_ptr == C_NULL
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_FILE_OPEN_FAILURE)
        return ErrorResult(last_error())
    end
    return Libc.FILE(file_ptr)
end

function FileInputStream(path::AbstractString)::Union{FileInputStream, ErrorResult}
    file = _file_open_read(path)
    if file isa ErrorResult
        return file
    end
    stream = FileInputStream(file, true)
    finalizer(stream_destroy!, stream)
    return stream
end

function FileInputStream(file::Libc.FILE; close_on_cleanup::Bool = false)
    stream = FileInputStream(file, close_on_cleanup)
    if close_on_cleanup
        finalizer(stream_destroy!, stream)
    end
    return stream
end

function stream_read(stream::FileInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    tracing_task_begin(tracing_input_stream_read)
    try
        if stream.file === nothing
            raise_error(ERROR_IO_STREAM_READ_FAILED)
            return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
        end

        space = buffer.capacity - buffer.len
        to_read = min(Csize_t(length), space)

        if to_read == 0
            return (Csize_t(0), StreamStatus.OK)
        end

        bytes_read = Csize_t(0)
        GC.@preserve buffer stream begin
            dest_ptr = pointer(buffer.mem) + Int(buffer.len)
            bytes_read = ccall(
                :fread,
                Csize_t,
                (Ptr{Cvoid}, Csize_t, Csize_t, Ptr{Cvoid}),
                dest_ptr,
                1,
                to_read,
                stream.file.ptr,
            )
        end

        if bytes_read == 0
            if ccall(:ferror, Cint, (Ptr{Cvoid},), stream.file.ptr) != 0
                raise_error(ERROR_IO_STREAM_READ_FAILED)
                return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
            end
        end

        if bytes_read > 0
            buffer.len = buffer.len + bytes_read
        end

        status = ccall(:feof, Cint, (Ptr{Cvoid},), stream.file.ptr) != 0 ?
            StreamStatus.END_OF_STREAM :
            StreamStatus.OK
        return (bytes_read, status)
    finally
        tracing_task_end(tracing_input_stream_read)
    end
end

function stream_seek(stream::FileInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    if stream.file === nothing
        raise_error(ERROR_STREAM_UNSEEKABLE)
        return ErrorResult(ERROR_STREAM_UNSEEKABLE)
    end

    whence = if basis == StreamSeekBasis.BEGIN
        _FILE_STREAM_SEEK_SET
    elseif basis == StreamSeekBasis.END
        _FILE_STREAM_SEEK_END
    else
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    rc = _file_stream_seek(stream.file, offset, whence)
    if rc != 0
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_STREAM_UNSEEKABLE)
        return ErrorResult(last_error())
    end

    return nothing
end

function stream_get_length(stream::FileInputStream)::Union{Int64, ErrorResult}
    if stream.file === nothing
        raise_error(ERROR_INVALID_FILE_HANDLE)
        return ErrorResult(ERROR_INVALID_FILE_HANDLE)
    end

    # Use seek/tell instead of `fileno`+`stat` for Windows portability.
    old_pos = _file_stream_tell(stream.file)
    if old_pos < 0
        err = Libc.errno()
        translate_and_raise_io_error(err)
        return ErrorResult(last_error())
    end

    rc = _file_stream_seek(stream.file, Int64(0), _FILE_STREAM_SEEK_END)
    if rc != 0
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_STREAM_UNSEEKABLE)
        return ErrorResult(last_error())
    end

    end_pos = _file_stream_tell(stream.file)
    if end_pos < 0
        err = Libc.errno()
        translate_and_raise_io_error(err)
        return ErrorResult(last_error())
    end

    rc = _file_stream_seek(stream.file, old_pos, _FILE_STREAM_SEEK_SET)
    if rc != 0
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_STREAM_UNSEEKABLE)
        return ErrorResult(last_error())
    end

    return end_pos
end

function stream_get_position(stream::FileInputStream)::Union{Int64, ErrorResult}
    if stream.file === nothing
        raise_error(ERROR_INVALID_FILE_HANDLE)
        return ErrorResult(ERROR_INVALID_FILE_HANDLE)
    end

    pos = _file_stream_tell(stream.file)
    if pos < 0
        err = Libc.errno()
        translate_and_raise_io_error(err)
        return ErrorResult(last_error())
    end

    return pos
end

function stream_is_seekable(stream::FileInputStream)::Bool
    return true
end

function stream_has_known_length(stream::FileInputStream)::Bool
    return true
end

function stream_destroy!(stream::FileInputStream)::Nothing
    if stream.file !== nothing && stream.close_on_cleanup
        try
            close(stream.file)
        catch
            # Ignore close errors
        end
    end
    stream.file = nothing
    return nothing
end

function stream_get_status(stream::FileInputStream)::Union{InputStreamStatus, ErrorResult}
    if stream.file === nothing
        return InputStreamStatus(true, false)
    end
    is_end = ccall(:feof, Cint, (Ptr{Cvoid},), stream.file.ptr) != 0
    is_valid = ccall(:ferror, Cint, (Ptr{Cvoid},), stream.file.ptr) == 0
    return InputStreamStatus(is_end, is_valid)
end

# =============================================================================
# Cursor Input Stream - reads from a ByteCursor (non-owning view)
# =============================================================================

mutable struct CursorInputStream <: AbstractInputStream
    cursor::ByteCursor
    position::Csize_t
end

function CursorInputStream(cursor::ByteCursor)
    return CursorInputStream(cursor, Csize_t(0))
end

function stream_read(stream::CursorInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    tracing_task_begin(tracing_input_stream_read)
    try
        available = stream.cursor.len - stream.position
        space = buffer.capacity - buffer.len
        to_read = min(Csize_t(length), available, space)

        if to_read == 0
            return (Csize_t(0), available == 0 ? StreamStatus.END_OF_STREAM : StreamStatus.OK)
        end

        src_ref = memref_advance(stream.cursor.ptr, Int(stream.position))
        src_mem = parent(src_ref)
        src_start = memref_offset(src_ref)
        copyto!(buffer.mem, Int(buffer.len) + 1, src_mem, src_start, Int(to_read))
        buffer.len = buffer.len + to_read

        stream.position += to_read

        status = stream.position >= stream.cursor.len ? StreamStatus.END_OF_STREAM : StreamStatus.OK
        return (to_read, status)
    finally
        tracing_task_end(tracing_input_stream_read)
    end
end

function stream_seek(stream::CursorInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    new_pos = if basis == StreamSeekBasis.BEGIN
        offset
    elseif basis == StreamSeekBasis.END
        Int64(stream.cursor.len) + offset
    else
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    if new_pos < 0 || new_pos > Int64(stream.cursor.len)
        raise_error(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
        return ErrorResult(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
    end

    stream.position = Csize_t(new_pos)
    return nothing
end

function stream_get_length(stream::CursorInputStream)::Union{Int64, ErrorResult}
    return Int64(stream.cursor.len)
end

function stream_get_position(stream::CursorInputStream)::Union{Int64, ErrorResult}
    return Int64(stream.position)
end

function stream_is_seekable(stream::CursorInputStream)::Bool
    return true
end

function stream_has_known_length(stream::CursorInputStream)::Bool
    return true
end

function stream_get_status(stream::CursorInputStream)::Union{InputStreamStatus, ErrorResult}
    is_end = stream.position >= stream.cursor.len
    return InputStreamStatus(is_end, true)
end

# =============================================================================
# Input stream constructors (aws-c-io parity)
# =============================================================================

input_stream_new_from_cursor(cursor::ByteCursor) = CursorInputStream(cursor)

function input_stream_new_from_file(path::AbstractString)
    return FileInputStream(path)
end

function input_stream_new_from_open_file(file::Libc.FILE)
    return FileInputStream(file; close_on_cleanup = false)
end

# =============================================================================
# Utility functions
# =============================================================================

# Read entire stream into a ByteBuffer
function stream_read_all(
        stream::AbstractInputStream,
        max_size::Integer = SIZE_MAX,
    )::Union{ByteBuffer, ErrorResult}
    # Try to get length if possible
    initial_size = if stream_has_known_length(stream)
        len_result = stream_get_length(stream)
        if len_result isa ErrorResult
            Csize_t(4096)
        else
            min(Csize_t(len_result), Csize_t(max_size))
        end
    else
        Csize_t(4096)
    end

    buffer = ByteBuffer(initial_size)
    chunk_size = Csize_t(4096)

    while true
        # Ensure we have capacity
        if buffer.len + chunk_size > buffer.capacity
            # Need to grow - create new buffer
            new_capacity = max(buffer.capacity * 2, buffer.len + chunk_size)
            new_capacity = min(new_capacity, Csize_t(max_size))

            if new_capacity <= buffer.len
                break  # Can't read more
            end

            new_buffer = ByteBuffer(new_capacity)
            # Copy existing data
            if buffer.len > 0
                copyto!(new_buffer.mem, 1, buffer.mem, 1, Int(buffer.len))
                new_buffer.len = buffer.len
            end
            buffer = new_buffer
        end

        # Read chunk
        read_result = stream_read(stream, buffer, chunk_size)

        if read_result isa ErrorResult
            return read_result
        end

        bytes_read, status = read_result

        if status == StreamStatus.END_OF_STREAM || bytes_read == 0
            break
        end

        if buffer.len >= Csize_t(max_size)
            break
        end
    end

    return buffer
end

# Copy from one stream to another (via a buffer)
function stream_copy(
        source::AbstractInputStream,
        dest_buffer::ByteBuffer,
        max_bytes::Integer = SIZE_MAX,
    )::Union{Csize_t, ErrorResult}
    total_copied = Csize_t(0)

    while total_copied < Csize_t(max_bytes)
        remaining = min(Csize_t(max_bytes) - total_copied, dest_buffer.capacity - dest_buffer.len)

        if remaining == 0
            break
        end

        read_result = stream_read(source, dest_buffer, remaining)

        if read_result isa ErrorResult
            return read_result
        end

        bytes_read, status = read_result
        total_copied += bytes_read

        if status == StreamStatus.END_OF_STREAM || bytes_read == 0
            break
        end
    end

    return total_copied
end

# Reset stream to beginning
function stream_reset(stream::AbstractInputStream)::Union{Nothing, ErrorResult}
    if !stream_is_seekable(stream)
        raise_error(ERROR_IO_STREAM_SEEK_UNSUPPORTED)
        return ErrorResult(ERROR_IO_STREAM_SEEK_UNSUPPORTED)
    end

    return stream_seek(stream, Int64(0), StreamSeekBasis.BEGIN)
end
