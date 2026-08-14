"""
    ReseauBufferIOExt

Integration between Reseau and BufferIO.jl, in three layers:

1. `Base.IO` bridge methods on `TCP.Conn` for MemoryViews buffers
   (`readbytes!`, `write`), which make the stock `BufferIO.BufReader` /
   `BufferIO.BufWriter` wrappers correct and syscall-efficient over a `Conn`.
2. Native `TCP.bufreader` / `TCP.bufwriter` implementations of
   `AbstractBufReader` / `AbstractBufWriter` that skip the generic wrappers'
   extra `eof` probe and use the connection's pointer I/O paths directly.
3. Nothing else: deadlines, close semantics, and error types are the
   connection's own, surfaced through buffer refills and flushes unchanged.
"""
module ReseauBufferIOExt

using Reseau: Reseau, TCP, IOPoll
using BufferIO: BufferIO, AbstractBufReader, AbstractBufWriter, IOError, IOErrorKinds
using MemoryViews: MemoryViews, MemoryView, ImmutableMemoryView, MutableMemoryView

# One short read into `v`: blocks until at least 1 byte arrives, returns 0 at
# EOF. The view is passed as the GC root so the backing Memory stays alive
# across an async (IOCP) completion.
function _read_some_into!(conn::TCP.Conn, v::MutableMemoryView{UInt8})::Int
    isempty(v) && return 0
    return try
        GC.@preserve v TCP._read_some!(conn, Base.unsafe_convert(Ptr{UInt8}, v), length(v), v)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
end

"""
    readbytes!(conn::TCP.Conn, v::MutableMemoryView{UInt8}, nb = length(v); all::Bool = false)

Read up to `nb` bytes from `conn` into the start of `v`, returning the number
of bytes read.

Unlike the `MutableByteBuffer` methods on `Conn`, `all` defaults to `false`:
the call blocks only until at least one byte is available (or EOF) and then
returns what a single read produced. This is the fill contract buffered
readers such as `BufferIO.BufReader` rely on when they call
`readbytes!(io, view)` — an `all = true` default would make a buffered
`readline` stall until the whole free buffer fills. Views cannot be resized,
so `nb` is clamped to `length(v)`.
"""
function Base.readbytes!(
        conn::TCP.Conn,
        v::MutableMemoryView{UInt8},
        nb::Integer = length(v);
        all::Bool = false,
    )::Int
    nb < 0 && throw(ArgumentError("readbytes! byte count must be non-negative"))
    requested = min(Int(nb), length(v))
    filled = 0
    while filled < requested
        n = _read_some_into!(conn, @inbounds v[(filled + 1):requested])
        n == 0 && break
        filled += n
        all || break
    end
    return filled
end

"""
    write(conn::TCP.Conn, v::MemoryViews.MemoryView{UInt8}) -> Int

Write the full view to `conn` without an intermediate copy and return the
number of bytes written.
"""
function Base.write(conn::TCP.Conn, v::MemoryView{UInt8})::Int
    isempty(v) && return 0
    GC.@preserve v begin
        return TCP._write_rooted!(conn, Base.unsafe_convert(Ptr{UInt8}, v), length(v), v)
    end
end

##########################
# Native reader
##########################

mutable struct ConnBufReader <: AbstractBufReader
    const conn::TCP.Conn
    buffer::Memory{UInt8}
    start::Int  # index of the first unread byte
    stop::Int   # index of the last valid byte; start > stop means empty
end

function TCP.bufreader(conn::TCP.Conn; buffer_size::Integer = 8192)::ConnBufReader
    buffer_size < 1 && throw(ArgumentError("buffer_size must be at least 1"))
    return ConnBufReader(conn, Memory{UInt8}(undef, Int(buffer_size)), 1, 0)
end

function BufferIO.get_buffer(r::ConnBufReader)::ImmutableMemoryView{UInt8}
    return @inbounds ImmutableMemoryView(r.buffer)[r.start:r.stop]
end

function BufferIO.fill_buffer(r::ConnBufReader)::Int
    if r.start > r.stop
        # Empty: reuse the whole buffer.
        r.start = 1
        r.stop = 0
    elseif r.stop == length(r.buffer)
        n_buffered = r.stop - r.start + 1
        if r.start > 1
            copyto!(r.buffer, 1, r.buffer, r.start, n_buffered)
        else
            # Full from index 1: grow so the fill contract can still add bytes.
            grown = Memory{UInt8}(undef, 2 * length(r.buffer))
            copyto!(grown, 1, r.buffer, 1, n_buffered)
            r.buffer = grown
        end
        r.start = 1
        r.stop = n_buffered
    end
    tail = @inbounds MemoryView(r.buffer)[(r.stop + 1):length(r.buffer)]
    n = _read_some_into!(r.conn, tail)
    r.stop += n
    return n
end

function BufferIO.consume(r::ConnBufReader, n::Int)::Nothing
    @boundscheck if (n % UInt) > ((r.stop - r.start + 1) % UInt)
        throw(IOError(IOErrorKinds.ConsumeBufferError))
    end
    r.start += n
    return nothing
end

Base.close(r::ConnBufReader) = close(r.conn)

function Base.show(io::IO, r::ConnBufReader)
    print(io, "TCP.bufreader(", r.conn, ", ", r.stop - r.start + 1, " bytes buffered)")
    return nothing
end

##########################
# Native writer
##########################

mutable struct ConnBufWriter <: AbstractBufWriter
    const conn::TCP.Conn
    buffer::Memory{UInt8}
    consumed::Int  # bytes written into the buffer but not yet flushed
    is_closed::Bool
end

function TCP.bufwriter(conn::TCP.Conn; buffer_size::Integer = 4096)::ConnBufWriter
    buffer_size < 1 && throw(ArgumentError("buffer_size must be at least 1"))
    return ConnBufWriter(conn, Memory{UInt8}(undef, Int(buffer_size)), 0, false)
end

function BufferIO.get_buffer(w::ConnBufWriter)::MutableMemoryView{UInt8}
    return @inbounds MemoryView(w.buffer)[(w.consumed + 1):length(w.buffer)]
end

function BufferIO.get_unflushed(w::ConnBufWriter)::MutableMemoryView{UInt8}
    return @inbounds MemoryView(w.buffer)[1:(w.consumed)]
end

function BufferIO.consume(w::ConnBufWriter, n::Int)::Nothing
    @boundscheck if (n % UInt) > ((length(w.buffer) - w.consumed) % UInt)
        throw(IOError(IOErrorKinds.ConsumeBufferError))
    end
    w.consumed += n
    return nothing
end

function BufferIO.shallow_flush(w::ConnBufWriter)::Int
    w.is_closed && throw(IOError(IOErrorKinds.ClosedIO))
    to_flush = w.consumed
    if !iszero(to_flush)
        buffer = w.buffer
        GC.@preserve buffer begin
            TCP._write_rooted!(w.conn, Base.unsafe_convert(Ptr{UInt8}, buffer), to_flush, buffer)
        end
        w.consumed = 0
    end
    return to_flush
end

function BufferIO.grow_buffer(w::ConnBufWriter)::Int
    flushed = BufferIO.shallow_flush(w)
    iszero(flushed) || return flushed
    # A zero-byte flush means the buffer held no pending data; just grow it.
    old_size = length(w.buffer)
    w.buffer = Memory{UInt8}(undef, 2 * old_size)
    return old_size
end

function Base.flush(w::ConnBufWriter)
    BufferIO.shallow_flush(w)
    flush(w.conn)
    return nothing
end

function Base.close(w::ConnBufWriter)
    w.is_closed && return nothing
    flush(w)
    w.is_closed = true
    close(w.conn)
    return nothing
end

function Base.show(io::IO, w::ConnBufWriter)
    print(io, "TCP.bufwriter(", w.conn, ", ", w.consumed, " bytes unflushed)")
    return nothing
end

end # module ReseauBufferIOExt
