# AWS IO Library - Stream Abstractions
# Port of aws-c-io/source/stream.c and include/aws/io/stream.h

# Stream seek basis
@enumx StreamSeekBasis::UInt8 begin
    BEGIN = 0
    CURRENT = 1
    END = 2
end

# Stream status
@enumx StreamStatus::UInt8 begin
    OK = 0
    END_OF_STREAM = 1
    ERROR = 2
end

# Abstract stream interface
abstract type AbstractInputStream end

# Stream vtable interface methods

# Read from stream into buffer, returns (bytes_read, status)
function stream_read(stream::AbstractInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    error("stream_read must be implemented for $(typeof(stream))")
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
    available = stream.buffer.len - stream.position
    to_read = min(Csize_t(length), available)

    if to_read == 0
        return (Csize_t(0), StreamStatus.END_OF_STREAM)
    end

    # Copy data
    src_start = Int(stream.position) + 1
    dst_start = Int(buffer.len) + 1
    copyto!(buffer.mem, dst_start, stream.buffer.mem, src_start, Int(to_read))
    buffer.len = buffer.len + to_read

    stream.position += to_read

    status = stream.position >= stream.buffer.len ? StreamStatus.END_OF_STREAM : StreamStatus.OK
    return (to_read, status)
end

function stream_seek(stream::ByteBufferInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    new_pos = if basis == StreamSeekBasis.BEGIN
        offset
    elseif basis == StreamSeekBasis.CURRENT
        Int64(stream.position) + offset
    else  # END
        Int64(stream.buffer.len) + offset
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

# =============================================================================
# File Input Stream - reads from a file
# =============================================================================

mutable struct FileInputStream <: AbstractInputStream
    path::String
    file_handle::Union{IOStream, Nothing}
    length::Int64
    position::Int64
end

function FileInputStream(path::AbstractString)::Union{FileInputStream, ErrorResult}
    # Check if file exists and get length
    if !isfile(path)
        raise_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        return ErrorResult(ERROR_IO_FILE_VALIDATION_FAILURE)
    end

    file_size = try
        filesize(path)
    catch
        raise_error(ERROR_IO_STREAM_GET_LENGTH_FAILED)
        return ErrorResult(ERROR_IO_STREAM_GET_LENGTH_FAILED)
    end

    # Open file
    file = try
        open(path, "r")
    catch
        raise_error(ERROR_IO_STREAM_READ_FAILED)
        return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
    end

    return FileInputStream(String(path), file, file_size, Int64(0))
end

function stream_read(stream::FileInputStream, buffer::ByteBuffer, length::Integer)::Union{Tuple{Csize_t, StreamStatus.T}, ErrorResult}
    if stream.file_handle === nothing
        raise_error(ERROR_IO_STREAM_READ_FAILED)
        return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
    end

    remaining = stream.length - stream.position
    to_read = min(Csize_t(length), Csize_t(remaining), buffer.capacity - buffer.len)

    if to_read == 0
        return (Csize_t(0), StreamStatus.END_OF_STREAM)
    end

    # Read into buffer
    data = Memory{UInt8}(undef, Int(to_read))

    bytes_read = try
        readbytes!(stream.file_handle, data, to_read)
    catch e
        logf(LogLevel.ERROR, LS_IO_FILE_UTILS, "File stream: read failed: $e")
        raise_error(ERROR_IO_STREAM_READ_FAILED)
        return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
    end

    if bytes_read > 0
        copyto!(buffer.mem, Int(buffer.len) + 1, data, 1, bytes_read)
        buffer.len = buffer.len + Csize_t(bytes_read)
        stream.position += bytes_read
    end

    status = stream.position >= stream.length ? StreamStatus.END_OF_STREAM : StreamStatus.OK
    return (Csize_t(bytes_read), status)
end

function stream_seek(stream::FileInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    if stream.file_handle === nothing
        raise_error(ERROR_IO_STREAM_SEEK_FAILED)
        return ErrorResult(ERROR_IO_STREAM_SEEK_FAILED)
    end

    new_pos = if basis == StreamSeekBasis.BEGIN
        offset
    elseif basis == StreamSeekBasis.CURRENT
        stream.position + offset
    else  # END
        stream.length + offset
    end

    if new_pos < 0 || new_pos > stream.length
        raise_error(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
        return ErrorResult(ERROR_IO_STREAM_INVALID_SEEK_POSITION)
    end

    try
        seek(stream.file_handle, new_pos)
        stream.position = new_pos
    catch
        raise_error(ERROR_IO_STREAM_SEEK_FAILED)
        return ErrorResult(ERROR_IO_STREAM_SEEK_FAILED)
    end

    return nothing
end

function stream_get_length(stream::FileInputStream)::Union{Int64, ErrorResult}
    return stream.length
end

function stream_get_position(stream::FileInputStream)::Union{Int64, ErrorResult}
    return stream.position
end

function stream_is_seekable(stream::FileInputStream)::Bool
    return true
end

function stream_has_known_length(stream::FileInputStream)::Bool
    return true
end

function stream_destroy!(stream::FileInputStream)::Nothing
    if stream.file_handle !== nothing
        try
            close(stream.file_handle)
        catch
            # Ignore close errors
        end
        stream.file_handle = nothing
    end
    return nothing
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
    available = stream.cursor.len - stream.position
    to_read = min(Csize_t(length), available, buffer.capacity - buffer.len)

    if to_read == 0
        return (Csize_t(0), StreamStatus.END_OF_STREAM)
    end

    src_ref = memref_advance(stream.cursor.ptr, Int(stream.position))
    src_mem = parent(src_ref)
    src_start = memref_offset(src_ref)
    copyto!(buffer.mem, Int(buffer.len) + 1, src_mem, src_start, Int(to_read))
    buffer.len = buffer.len + to_read

    stream.position += to_read

    status = stream.position >= stream.cursor.len ? StreamStatus.END_OF_STREAM : StreamStatus.OK
    return (to_read, status)
end

function stream_seek(stream::CursorInputStream, offset::Int64, basis::StreamSeekBasis.T)::Union{Nothing, ErrorResult}
    new_pos = if basis == StreamSeekBasis.BEGIN
        offset
    elseif basis == StreamSeekBasis.CURRENT
        Int64(stream.position) + offset
    else  # END
        Int64(stream.cursor.len) + offset
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
