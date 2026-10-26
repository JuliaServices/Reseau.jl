# Bookkeeping for QUIC connections: sets of integer ranges, the CRYPTO stream's
# send and receive buffers (RFC 9000 Sections 7.5, 13.3), and the same for
# application streams (Sections 2 to 4).

"""
    _RangeSet

Sorted, disjoint, non-adjacent `Int64` ranges. Tracks received packet numbers
for ACK frames and acknowledged or pending CRYPTO bytes.
"""
struct _RangeSet
    ranges::Vector{UnitRange{Int64}}
end

_RangeSet() = _RangeSet(UnitRange{Int64}[])

Base.isempty(s::_RangeSet) = isempty(s.ranges)
Base.length(s::_RangeSet) = length(s.ranges)
Base.iterate(s::_RangeSet, i::Int = 1) = i > length(s.ranges) ? nothing : (s.ranges[i], i + 1)
Base.eltype(::Type{_RangeSet}) = UnitRange{Int64}
Base.empty!(s::_RangeSet) = (empty!(s.ranges); s)

function Base.in(x::Integer, s::_RangeSet)::Bool
    i = searchsortedfirst(s.ranges, x; by = r -> r isa UnitRange ? r.stop : r)
    return i <= length(s.ranges) && first(s.ranges[i]) <= x
end

_range_set_max(s::_RangeSet)::Int64 = last(s.ranges[end])

"""
    push!(s::_RangeSet, r)

Add `r`, merging it with any range it overlaps or touches.
"""
function Base.push!(s::_RangeSet, r::UnitRange{Int64})::_RangeSet
    isempty(r) && return s
    ranges = s.ranges
    # The first range that could touch `r`, and the last.
    lo = searchsortedfirst(ranges, first(r) - 1; by = x -> x isa UnitRange ? last(x) : x)
    hi = searchsortedlast(ranges, last(r) + 1; by = x -> x isa UnitRange ? first(x) : x)
    if lo > hi
        insert!(ranges, lo, r)
    else
        merged = min(first(r), first(ranges[lo])):max(last(r), last(ranges[hi]))
        ranges[lo] = merged
        deleteat!(ranges, (lo + 1):hi)
    end
    return s
end

"""
    delete!(s::_RangeSet, r)

Remove every value in `r`, splitting ranges as needed.
"""
function Base.delete!(s::_RangeSet, r::UnitRange{Int64})::_RangeSet
    isempty(r) && return s
    ranges = s.ranges
    # The ranges `r` overlaps: the first ending at or after it starts, through
    # the last starting at or before it ends.
    lo = searchsortedfirst(ranges, first(r); by = x -> x isa UnitRange ? last(x) : x)
    hi = searchsortedlast(ranges, last(r); by = x -> x isa UnitRange ? first(x) : x)
    lo > hi && return s
    left = first(ranges[lo]):(first(r) - 1)
    right = (last(r) + 1):last(ranges[hi])
    # Replace ranges[lo:hi] by what is left of them, in place.
    keep = (isempty(left) ? 0 : 1) + (isempty(right) ? 0 : 1)
    i = lo
    isempty(left) || (ranges[i] = left; i += 1)
    if !isempty(right)
        if i <= hi
            ranges[i] = right
        else
            insert!(ranges, i, right)
            return s
        end
        i += 1
    end
    i <= hi && deleteat!(ranges, i:hi)
    return s
end

"Ranges largest first, as `UnitRange{UInt64}`s for an ACK frame."
_descending_ranges(s::_RangeSet)::Vector{UnitRange{UInt64}} =
    [UInt64(first(r)):UInt64(last(r)) for r in Iterators.reverse(s.ranges)]

"Drop the smallest ranges so at most `n` remain, bounding ACK frame size."
function _keep_largest_ranges!(s::_RangeSet, n::Int)::Nothing
    excess = length(s.ranges) - n
    excess > 0 && deleteat!(s.ranges, 1:excess)
    return nothing
end

# How far past the delivered offset a peer's CRYPTO data may reach. RFC 9000
# Section 7.5 requires at least 4096 bytes.
const _CRYPTO_BUFFER_LIMIT = 65536

"""
    _Reassembly

Puts a byte stream that arrives in pieces back in order. `delivered` is the
offset of the next byte to hand on; `fragments` holds out-of-order data by
offset, sorted and disjoint, so a repeated fragment is stored once.
"""
mutable struct _Reassembly
    delivered::Int64
    fragments::Vector{Tuple{Int64, Vector{UInt8}}}
end

_Reassembly() = _Reassembly(Int64(0), Tuple{Int64, Vector{UInt8}}[])

"""
    _reassemble!(out, rb, start, data)

Take `data` at offset `start` and append to `out` the bytes that are now
contiguous with what was delivered before, possibly none.
"""
function _reassemble!(out::Vector{UInt8}, rb::_Reassembly, start::Int64, data::AbstractVector{UInt8})::Nothing
    stop = start + length(data)  # exclusive
    stop <= rb.delivered && return nothing
    if start > rb.delivered
        _hold_fragment!(rb, start, data)
        return nothing
    end
    append!(out, @view(data[(rb.delivered - start + 1):end]))
    rb.delivered = stop
    # Held fragments that now touch the delivered prefix follow it.
    while !isempty(rb.fragments) && rb.fragments[1][1] <= rb.delivered
        frag_start, frag = popfirst!(rb.fragments)
        frag_stop = frag_start + length(frag)
        if frag_stop > rb.delivered
            append!(out, @view(frag[(rb.delivered - frag_start + 1):end]))
            rb.delivered = frag_stop
        end
    end
    return nothing
end

# Holds the parts of `data` (at `start`) that no held fragment covers yet.
function _hold_fragment!(rb::_Reassembly, start::Int64, data::AbstractVector{UInt8})::Nothing
    stop = start + length(data)
    frags = rb.fragments
    # The first fragment that ends after `start`.
    i = searchsortedfirst(frags, start; by = f -> f isa Tuple ? f[1] + length(f[2]) : f)
    pos = start
    while pos < stop
        if i <= length(frags) && frags[i][1] <= pos
            pos = frags[i][1] + length(frags[i][2])
            i += 1
            continue
        end
        gap_stop = i <= length(frags) ? min(stop, frags[i][1]) : stop
        insert!(frags, i, (pos, Vector{UInt8}(@view(data[(pos - start + 1):(gap_stop - start)]))))
        i += 1
        pos = gap_stop
    end
    return nothing
end

"""
    _crypto_receive!(rb, offset, data) -> Vector{UInt8} or _TransportError

Take a CRYPTO frame's data and return the bytes that are now contiguous with
what was delivered before, possibly none.
"""
function _crypto_receive!(rb::_Reassembly, offset::UInt64, data::AbstractVector{UInt8})::Union{Vector{UInt8}, _TransportError}
    start = Int64(offset)
    start + length(data) > rb.delivered + _CRYPTO_BUFFER_LIMIT &&
        return _TransportError(_CRYPTO_BUFFER_EXCEEDED, UInt64(0x06), "CRYPTO data too far ahead")
    out = UInt8[]
    _reassemble!(out, rb, start, data)
    return out
end

"""
    _CryptoSendBuffer

One encryption level's outgoing CRYPTO stream. `data` holds every byte queued
so far (offset 0 is `data[1]`); `pending` is what still needs sending, new or
lost; `acked` is what the peer has acknowledged.
"""
struct _CryptoSendBuffer
    data::Vector{UInt8}
    pending::_RangeSet
    acked::_RangeSet
end

_CryptoSendBuffer() = _CryptoSendBuffer(UInt8[], _RangeSet(), _RangeSet())

function _crypto_queue!(sb::_CryptoSendBuffer, bytes::AbstractVector{UInt8})::Nothing
    isempty(bytes) && return nothing
    start = Int64(length(sb.data))
    append!(sb.data, bytes)
    push!(sb.pending, start:(start + length(bytes) - 1))
    return nothing
end

_crypto_has_pending(sb::_CryptoSendBuffer)::Bool = !isempty(sb.pending)

"""
    _crypto_next_chunk!(sb, max_len) -> UnitRange{Int64} or nothing

Take up to `max_len` bytes from the lowest pending offset.
"""
function _crypto_next_chunk!(sb::_CryptoSendBuffer, max_len::Int)::Union{Nothing, UnitRange{Int64}}
    (isempty(sb.pending) || max_len <= 0) && return nothing
    r = first(sb.pending.ranges)
    chunk = first(r):min(last(r), first(r) + max_len - 1)
    delete!(sb.pending, chunk)
    return chunk
end

_crypto_bytes(sb::_CryptoSendBuffer, r::UnitRange{Int64}) = @view sb.data[(first(r) + 1):(last(r) + 1)]

_crypto_on_acked!(sb::_CryptoSendBuffer, r::UnitRange{Int64})::Nothing = (push!(sb.acked, r); nothing)

"Queue `r` for resending, less anything acknowledged since it was sent."
function _crypto_on_lost!(sb::_CryptoSendBuffer, r::UnitRange{Int64})::Nothing
    lost = _RangeSet()
    push!(lost, r)
    for acked in sb.acked
        delete!(lost, acked)
    end
    for x in lost
        push!(sb.pending, x)
    end
    return nothing
end

# Buffers release their consumed prefix once it is this large and over half
# the buffer, so each byte is moved O(1) times on average.
const _COMPACT_THRESHOLD = 4096

"""
    _StreamSendBuffer

One stream's outgoing bytes. `data[start]` holds offset `base`; everything
below `base` was acknowledged and released. `pending` is what still needs
sending, new or lost; `acked` is what the peer acknowledged at or past `base`;
`max_sent` is one past the highest offset ever sent, the flow-control credit
used. `fin` means the application finished the stream.
"""
mutable struct _StreamSendBuffer
    data::Vector{UInt8}
    start::Int
    base::Int64
    pending::_RangeSet
    acked::_RangeSet
    max_sent::Int64
    fin::Bool
    fin_pending::Bool
    fin_acked::Bool
end

_StreamSendBuffer() = _StreamSendBuffer(UInt8[], 1, Int64(0), _RangeSet(), _RangeSet(), Int64(0), false, false, false)

"One past the last offset written: the stream's final size once finished."
_send_end(sb::_StreamSendBuffer)::Int64 = sb.base + (length(sb.data) - sb.start + 1)

function _send_write!(sb::_StreamSendBuffer, bytes::AbstractVector{UInt8})::Nothing
    sb.fin && throw(ArgumentError("QUIC stream was already finished"))
    isempty(bytes) && return nothing
    stop = _send_end(sb)
    append!(sb.data, bytes)
    push!(sb.pending, stop:(stop + length(bytes) - 1))
    return nothing
end

function _send_finish!(sb::_StreamSendBuffer)::Nothing
    sb.fin && return nothing
    sb.fin = true
    sb.fin_pending = true
    return nothing
end

_send_has_pending(sb::_StreamSendBuffer)::Bool = !isempty(sb.pending) || sb.fin_pending

"""
    _send_next_chunk!(sb, max_len, limit) -> (range, fin) or nothing

Take up to `max_len` bytes from the lowest pending offset, sending nothing at
or past `limit` (the flow-control limit) for the first time. `fin` marks a
chunk that ends the stream; a FIN with no data left comes as an empty range.
"""
function _send_next_chunk!(sb::_StreamSendBuffer, max_len::Int, limit::Int64)::Union{Nothing, Tuple{UnitRange{Int64}, Bool}}
    if !isempty(sb.pending)
        r = first(sb.pending.ranges)
        (first(r) < limit && max_len > 0) || return nothing
        stop = min(last(r), first(r) + max_len - 1, limit - 1)
        chunk = first(r):stop
        delete!(sb.pending, chunk)
        sb.max_sent = max(sb.max_sent, stop + 1)
        fin = sb.fin_pending && stop + 1 == _send_end(sb)
        fin && (sb.fin_pending = false)
        return chunk, fin
    end
    sb.fin_pending || return nothing
    sb.fin_pending = false
    stop = _send_end(sb)
    return stop:(stop - 1), true
end

function _send_bytes(sb::_StreamSendBuffer, r::UnitRange{Int64})
    first_index = sb.start + Int(first(r) - sb.base)
    return @view sb.data[first_index:(first_index + length(r) - 1)]
end

function _send_on_acked!(sb::_StreamSendBuffer, r::UnitRange{Int64}, fin::Bool)::Nothing
    fin && (sb.fin_acked = true)
    isempty(r) || push!(sb.acked, r)
    # Release the acknowledged prefix.
    if !isempty(sb.acked) && first(sb.acked.ranges[1]) <= sb.base
        new_base = last(sb.acked.ranges[1]) + 1
        if new_base > sb.base
            sb.start += Int(new_base - sb.base)
            sb.base = new_base
        end
        popfirst!(sb.acked.ranges)
        if sb.start > _COMPACT_THRESHOLD && 2 * sb.start > length(sb.data)
            deleteat!(sb.data, 1:(sb.start - 1))
            sb.start = 1
        end
    end
    return nothing
end

"Queue `r` (and the FIN, if `fin`) for resending, less anything acknowledged since."
function _send_on_lost!(sb::_StreamSendBuffer, r::UnitRange{Int64}, fin::Bool)::Nothing
    fin && !sb.fin_acked && (sb.fin_pending = true)
    lost = _RangeSet()
    push!(lost, max(first(r), sb.base):last(r))
    for acked in sb.acked
        delete!(lost, acked)
    end
    for x in lost
        push!(sb.pending, x)
    end
    return nothing
end

_send_all_acked(sb::_StreamSendBuffer)::Bool = sb.fin_acked && sb.base == _send_end(sb)

"""
    _StreamReceiveBuffer

One stream's incoming bytes: reassembled data waiting for the application in
`ready[ready_pos:end]`, `read_offset` bytes already read, the highest offset
received (the flow-control credit used), and the final size once known (-1
before).
"""
mutable struct _StreamReceiveBuffer
    reassembly::_Reassembly
    ready::Vector{UInt8}
    ready_pos::Int
    read_offset::Int64
    max_received::Int64
    final_size::Int64
end

_StreamReceiveBuffer() = _StreamReceiveBuffer(_Reassembly(), UInt8[], 1, Int64(0), Int64(0), Int64(-1))

"""
    _recv_insert!(rb, offset, data, fin) -> nothing or error code

Take a STREAM frame's data. Returns FINAL_SIZE_ERROR for data past the final
size or a FIN that contradicts it (RFC 9000 Section 4.5). Flow control is the
caller's to check, against `offset + length(data)`.
"""
function _recv_insert!(rb::_StreamReceiveBuffer, offset::Int64, data::AbstractVector{UInt8}, fin::Bool)::Union{Nothing, UInt64}
    stop = offset + length(data)
    if rb.final_size >= 0
        stop > rb.final_size && return _FINAL_SIZE_ERROR
        fin && stop != rb.final_size && return _FINAL_SIZE_ERROR
    elseif fin
        stop < rb.max_received && return _FINAL_SIZE_ERROR
        rb.final_size = stop
    end
    rb.max_received = max(rb.max_received, stop)
    _reassemble!(rb.ready, rb.reassembly, offset, data)
    return nothing
end

"Learn the final size from RESET_STREAM; FINAL_SIZE_ERROR if it contradicts what is known."
function _recv_set_final_size!(rb::_StreamReceiveBuffer, size::Int64)::Union{Nothing, UInt64}
    if rb.final_size >= 0
        size == rb.final_size || return _FINAL_SIZE_ERROR
    else
        size < rb.max_received && return _FINAL_SIZE_ERROR
        rb.final_size = size
    end
    rb.max_received = max(rb.max_received, size)
    return nothing
end

_recv_readable(rb::_StreamReceiveBuffer)::Int = length(rb.ready) - rb.ready_pos + 1

function _recv_read!(rb::_StreamReceiveBuffer, max_len::Int)::Vector{UInt8}
    out = Vector{UInt8}(undef, min(max_len, _recv_readable(rb)))
    _recv_read_into!(rb, out, 1, length(out))
    return out
end

# Moves up to `max_len` readable bytes into `dst[doff:...]`; returns how many.
function _recv_read_into!(rb::_StreamReceiveBuffer, dst::AbstractVector{UInt8}, doff::Int, max_len::Int)::Int
    n = min(max_len, _recv_readable(rb))
    n > 0 && copyto!(dst, doff, rb.ready, rb.ready_pos, n)
    rb.ready_pos += n
    rb.read_offset += n
    if rb.ready_pos > length(rb.ready)
        empty!(rb.ready)
        rb.ready_pos = 1
    elseif rb.ready_pos > _COMPACT_THRESHOLD && 2 * rb.ready_pos > length(rb.ready)
        deleteat!(rb.ready, 1:(rb.ready_pos - 1))
        rb.ready_pos = 1
    end
    return n
end

"Whether the application has read everything up to the final size."
_recv_finished(rb::_StreamReceiveBuffer)::Bool = rb.final_size >= 0 && rb.read_offset == rb.final_size
