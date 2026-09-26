# Plain socket stream IO shared by the concrete TCP and Unix connections.

abstract type _StreamConn <: IO end

@inline function _read_some!(conn::_StreamConn, buf::MutableByteBuffer)::Int
    return IOPoll.read!(conn.fd.pfd, buf)
end

@inline function _read_some!(conn::_StreamConn, ptr::Ptr{UInt8}, nbytes::Int, root=nothing)::Int
    return IOPoll._read_ptr_some!(conn.fd.pfd, ptr, nbytes, root)
end

function _grow_readbytes_target!(buf::Vector{UInt8}, current::Int, nb::Int)::Int
    newlen = if current == 0
        min(nb, 1024)
    else
        min(nb, current * 2)
    end
    resize!(buf, newlen)
    return newlen
end

function _peek_eof(conn::_StreamConn)::Bool
    pfd = conn.fd.pfd
    pref = Ref{UInt8}(0x00)
    try
        IOPoll._fd_read_lock!(pfd)
    catch err
        ex = err::Exception
        ex isa IOPoll.NetClosingError || rethrow(ex)
        # A close that lands between the caller's isopen check and taking the
        # read lock reports EOF instead of surfacing the closing error.
        return true
    end
    try
        while true
            IOPoll.prepareread(pfd.pd, pfd.is_file)
            n = GC.@preserve pref SocketOps.recv_from!(
                pfd.sysfd,
                Base.unsafe_convert(Ptr{UInt8}, pref),
                Csize_t(1),
                SocketOps.MSG_PEEK,
            )
            if n > 0
                return false
            end
            n == 0 && return true
            errno = SocketOps.last_error()
            if errno == Int32(Base.Libc.EAGAIN) && IOPoll.pollable(pfd.pd)
                IOPoll.waitread(pfd.pd, pfd.is_file)
                continue
            end
            throw(SystemError("recv(MSG_PEEK)", Int(errno)))
        end
    finally
        IOPoll._fd_read_unlock!(pfd)
    end
end

"""
    unsafe_read(conn, ptr, nbytes)

Read exactly `nbytes` into `ptr` or throw `EOFError`.

This is the primitive that powers Julia's standard `read!` behavior once
the connection participates in the `IO` hierarchy.
"""
function Base.unsafe_read(conn::_StreamConn, ptr::Ptr{UInt8}, nbytes::UInt)
    remaining = Int(nbytes)
    if remaining == 0
        _read_some!(conn, ptr, 0)
        return nothing
    end
    offset = 0
    while remaining > 0
        n = _read_some!(conn, ptr + offset, remaining)
        offset += n
        remaining -= n
    end
    return nothing
end

function _readbytes_all!(conn::_StreamConn, buf::Vector{UInt8}, requested::Int)::Int
    original_len = length(buf)
    current_len = original_len
    bytes_read = 0
    while bytes_read < requested
        if current_len == 0 || bytes_read == current_len
            current_len = _grow_readbytes_target!(buf, current_len, requested)
        end
        chunk_capacity = min(current_len - bytes_read, requested - bytes_read)
        n = try
            GC.@preserve buf _read_some!(conn, pointer(buf, bytes_read + 1), chunk_capacity, buf)
        catch err
            ex = err::Exception
            ex isa EOFError || rethrow(ex)
            break
        end
        bytes_read += n
    end
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

function _readbytes_some!(conn::_StreamConn, buf::Vector{UInt8}, requested::Int)::Int
    original_len = length(buf)
    requested > original_len && resize!(buf, requested)
    bytes_read = try
        GC.@preserve buf _read_some!(conn, pointer(buf), requested, buf)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
    current_len = length(buf)
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

function _readbytes_all!(conn::_StreamConn, buf::MutableByteBuffer, requested::Int)::Int
    requested <= length(buf) || throw(ArgumentError("nb exceeds fixed-size buffer length"))
    bytes_read = 0
    while bytes_read < requested
        n = try
            GC.@preserve buf _read_some!(conn, pointer(buf, bytes_read + 1), requested - bytes_read, buf)
        catch err
            ex = err::Exception
            ex isa EOFError || rethrow(ex)
            break
        end
        bytes_read += n
    end
    return bytes_read
end

function _readbytes_some!(conn::_StreamConn, buf::MutableByteBuffer, requested::Int)::Int
    requested <= length(buf) || throw(ArgumentError("nb exceeds fixed-size buffer length"))
    return try
        GC.@preserve buf _read_some!(conn, pointer(buf), requested, buf)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
end

"""
    read!(conn, buf) -> buf

Read exactly `length(buf)` bytes into `buf` or throw `EOFError`.

Because `Conn <: IO`, Base's generic `read!` implementation already supports
mutable byte views like `@view bytes[2:5]` in addition to plain vectors.

Use `readbytes!` or `readavailable` when you want a count-returning read that
may stop early.
"""
Base.read!(conn::_StreamConn, buf)

"""
    readbytes!(conn, buf, nb=length(buf); all::Bool=true) -> Int

Read up to `nb` bytes into `buf`, returning the byte count.

Unlike `read!(conn, buf)`, this API may return after a short read or EOF. It is
the count-returning read entrypoint for a plain socket stream.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying socket read is performed.

Resizable `Vector{UInt8}` buffers grow when needed, matching Julia's standard
`readbytes!` behavior. Fixed-size contiguous byte views must satisfy
`nb <= length(buf)`.
"""
function Base.readbytes!(conn::_StreamConn, buf::MutableByteBuffer, nb::Integer = length(buf); all::Bool = true)::Int
    Base.require_one_based_indexing(buf)
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    if requested == 0
        _read_some!(conn, Ptr{UInt8}(C_NULL), 0)
        return 0
    end
    return all ? _readbytes_all!(conn, buf, requested) : _readbytes_some!(conn, buf, requested)
end

"""
    read(conn, nb::Integer; all::Bool=true) -> Vector{UInt8}

Read and return up to `nb` bytes from `conn`.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying socket read is performed.
"""
function Base.read(conn::_StreamConn, nb::Integer; all::Bool = true)::Vector{UInt8}
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    buf = Vector{UInt8}(undef, all && requested == typemax(Int) ? 1024 : requested)
    n = readbytes!(conn, buf, requested; all = all)
    return resize!(buf, n)
end

"""
    readavailable(conn) -> Vector{UInt8}

Read and return the bytes that are currently ready without requiring a
full-buffer exact read.
"""
function Base.readavailable(conn::_StreamConn)::Vector{UInt8}
    buf = Vector{UInt8}(undef, Base.SZ_UNBUFFERED_IO)
    n = try
        _read_some!(conn, buf)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        return UInt8[]
    end
    return resize!(buf, n)
end

# The `Ref` roots the Windows overlapped op (mirroring `write(conn, ::UInt8)`)
# so single-byte reads avoid the pointer-only bounce path.
function Base.read(conn::_StreamConn, ::Type{UInt8})::UInt8
    ref = Ref{UInt8}(0x00)
    GC.@preserve ref begin
        ptr = Base.unsafe_convert(Ptr{UInt8}, ref)
        n = 0
        while n == 0
            n = _read_some!(conn, ptr, 1, ref)
        end
    end
    return ref[]
end

"""
    eof(conn) -> Bool

Report whether the peer has cleanly closed the read side of the connection.
"""
function Base.eof(conn::_StreamConn)::Bool
    isopen(conn) || return true
    return _peek_eof(conn)
end

"""
    tryread!(conn, buf) -> Union{Int, Nothing}

Copy currently available bytes into a nonempty contiguous mutable byte buffer.
Return the byte count, `0` at EOF (including a locally closed connection), or
`nothing` if no bytes are ready or another reader owns the connection. Never
wait for network input or for the read lock. A short read is not EOF.

Read deadlines and transport errors apply as for ordinary reads. The caller
owns the returned bytes; subsequent reads continue after them. Use `read!` or
`readbytes!` when waiting for input is intended.
"""
function tryread!(conn::_StreamConn, buf::MutableByteBuffer)::Union{Int, Nothing}
    Base.require_one_based_indexing(buf)
    isempty(buf) && throw(ArgumentError("tryread! requires a nonempty buffer"))
    GC.@preserve buf return _tryread!(conn, pointer(buf), length(buf))
end

function _tryread!(conn::_StreamConn, ptr::Ptr{UInt8}, nbytes::Int)::Union{Int, Nothing}
    isopen(conn) || return 0
    pfd = conn.fd.pfd
    IOPoll._fdlock_rwlock!(pfd.fdlock, true, false) || return nothing
    try
        IOPoll.prepareread(pfd.pd, pfd.is_file, false)
        # All stream descriptors, including IOCP sockets, are nonblocking. The
        # read lock excludes overlapped reads while this synchronous recv runs.
        n = SocketOps.recv_from!(pfd.sysfd, ptr, Csize_t(min(nbytes, 1 << 30)))
        n >= 0 && return Int(n)
        errno = SocketOps.last_error()
        errno == Int32(Base.Libc.EAGAIN) && return nothing
        throw(SystemError("recv", Int(errno)))
    finally
        IOPoll._fd_read_unlock!(pfd)
    end
end

"""
    isopen(conn) -> Bool

Return `true` while `conn` still owns an open socket.
"""
function Base.isopen(conn::_StreamConn)::Bool
    return !IOPoll._fdlock_closing(conn.fd.pfd.fdlock)
end

function Base.flush(::_StreamConn)
    return nothing
end

@inline function _write_rooted!(conn::_StreamConn, ptr::Ptr{UInt8}, nbytes::Int, root)::Int
    return IOPoll._write_ptr!(conn.fd.pfd, ptr, nbytes, root)
end

"""
    write(conn, byte::UInt8) -> Int

Write one byte to the connection and return `1`.
"""
function Base.write(conn::_StreamConn, byte::UInt8)::Int
    ref = Ref{UInt8}(byte)
    GC.@preserve ref begin
        return _write_rooted!(conn, Base.unsafe_convert(Ptr{UInt8}, ref), 1, ref)
    end
end

"""
    unsafe_write(conn, ptr, nbytes)

Write exactly `nbytes` from `ptr`, returning the number of bytes written.
"""
function Base.unsafe_write(conn::_StreamConn, ptr::Ptr{UInt8}, nbytes::UInt)
    return IOPoll._write_ptr!(conn.fd.pfd, ptr, Int(nbytes))
end

"""
    write(conn, buf) -> Int

Write all bytes from `buf` and return the number of bytes written.

On success, the return value is always `length(buf)`. If the socket cannot
currently accept data, the call waits for write readiness and resumes until the
entire buffer has been written or an error/deadline interrupts the operation.
"""
Base.write(conn::_StreamConn, buf::AbstractVector{UInt8})

function Base.write(conn::_StreamConn, buf::Vector{UInt8})::Int
    GC.@preserve buf begin
        return _write_rooted!(conn, pointer(buf), length(buf), buf)
    end
end

function Base.write(conn::_StreamConn, buf::StridedVector{UInt8})::Int
    if stride(buf, 1) == 1
        return GC.@preserve buf _write_rooted!(conn, pointer(buf), length(buf), buf)
    end
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return _write_rooted!(conn, pointer(data), length(data), data)
    end
end

function Base.write(conn::_StreamConn, buf::Base.CodeUnits{UInt8,<:AbstractString})::Int
    return GC.@preserve buf _write_rooted!(conn, pointer(buf), length(buf), buf)
end

# Specialize Base's String write (which funnels through `unsafe_write`) so the
# string itself roots the Windows overlapped op instead of being copied
# through the pointer-only bounce path.
function Base.write(conn::_StreamConn, s::Union{String, SubString{String}})::Int
    GC.@preserve s begin
        return _write_rooted!(conn, pointer(s), sizeof(s), s)
    end
end

function Base.write(conn::_StreamConn, buf::AbstractVector{UInt8})::Int
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return _write_rooted!(conn, pointer(data), length(data), data)
    end
end

"""
    write(conn, buf, nbytes) -> Int

Write the first `nbytes` bytes from `buf` and return the number of bytes
written.

On success, the return value is always exactly `nbytes`. Like the `Vector`
overload, this may block waiting for write readiness between partial kernel
writes.
"""
function Base.write(conn::_StreamConn, buf::ByteMemory, nbytes::Integer)::Int
    n = Int(nbytes)
    n < 0 && throw(ArgumentError("nbytes must be >= 0"))
    n <= length(buf) || throw(ArgumentError("nbytes exceeds buffer length"))
    GC.@preserve buf begin
        return _write_rooted!(conn, pointer(buf), n, buf)
    end
end

"""
    close(conn)

Close the connection. Repeated closes are treated as no-ops.
"""
function Base.close(conn::_StreamConn)
    close(conn.fd)
    return nothing
end

"""
    closeread(conn)

Shut down the read side of the connection.
"""
function closeread(conn::_StreamConn)
    IOPoll.shutdown_socket!(conn.fd.pfd, SocketOps.SHUT_RD)
    return nothing
end

"""
    closewrite(conn)

Shut down the write side of the connection.
"""
function Base.closewrite(conn::_StreamConn)
    IOPoll.shutdown_socket!(conn.fd.pfd, SocketOps.SHUT_WR)
    return nothing
end

"""
    close(fd)

Close a net descriptor. Repeated closes are treated as no-op.
"""
function Base.close(fd::FD)
    try
        close(fd.pfd)
    catch err
        ex = err::Exception
        ex isa IOPoll.NetClosingError || rethrow(ex)
    end
    return nothing
end

"""
    set_deadline!(conn, deadline_ns)

Set both read and write deadlines on `conn`.

- `deadline_ns` is an absolute monotonic timestamp in nanoseconds, using the
  same clock as `time_ns()`.
- `deadline_ns == 0` disables both deadlines.
- `deadline_ns <= time_ns()` marks both sides as immediately timed out.

After the deadline is reached, blocking `read!`/`write` operations fail with
`DeadlineExceededError` until the deadline is cleared or moved forward.
"""
function set_deadline!(conn::_StreamConn, deadline_ns::Integer)
    IOPoll.set_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

"""
    set_read_deadline!(conn, deadline_ns)

Set only the read deadline on `conn`.

- Uses absolute monotonic nanoseconds (`time_ns()` clock).
- `deadline_ns == 0` disables read timeouts.
- `deadline_ns <= time_ns()` causes read waits to time out immediately.

This affects `read!` wait paths only.
"""
function set_read_deadline!(conn::_StreamConn, deadline_ns::Integer)
    IOPoll.set_read_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

"""
    set_write_deadline!(conn, deadline_ns)

Set only the write deadline on `conn`.

- Uses absolute monotonic nanoseconds (`time_ns()` clock).
- `deadline_ns == 0` disables write timeouts.
- `deadline_ns <= time_ns()` causes write waits to time out immediately.

This affects `write` wait paths only.
"""
function set_write_deadline!(conn::_StreamConn, deadline_ns::Integer)
    IOPoll.set_write_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

"""
    rawfd(conn) -> RawFD or Base.WindowsRawSocket

Return the OS-level socket descriptor backing `conn` (a `RawFD` on POSIX, a
`Base.WindowsRawSocket` on Windows) for FFI and interop.

Reseau retains ownership: the descriptor is non-blocking and registered with
the internal poller; callers must not close it, change its flags, or use it
after `close(conn)`. The result is a borrowed snapshot. Keep `conn` reachable,
for example with `GC.@preserve`, and prevent a concurrent `close(conn)` for the
full external operation. Throws `NetClosingError` if the socket is already
closing.
"""
function rawfd(conn::_StreamConn)
    return _rawfd(conn.fd)
end

function _rawfd(fd::FD)
    return IOPoll._with_fd_ref(fd.pfd) do sysfd
        @static if Sys.iswindows()
            return Base.WindowsRawSocket(Ptr{Cvoid}(sysfd))
        else
            return RawFD(sysfd)
        end
    end
end
