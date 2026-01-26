const UUID_STR_LEN = 37

struct uuid
    uuid_data::NTuple{16, UInt8}
end

const _UUID_DATA_OFFSET = fieldoffset(uuid, 1)
const _hex_digits = UInt8[
    UInt8('0'), UInt8('1'), UInt8('2'), UInt8('3'), UInt8('4'), UInt8('5'), UInt8('6'), UInt8('7'),
    UInt8('8'), UInt8('9'), UInt8('a'), UInt8('b'), UInt8('c'), UInt8('d'), UInt8('e'), UInt8('f'),
]

@inline function _uuid_bytes_ptr(uuid::Ptr{uuid})
    return Ptr{UInt8}(Ptr{UInt8}(uuid) + _UUID_DATA_OFFSET)
end

function uuid_init(uuid::Ptr{uuid})
    precondition(uuid != C_NULL)
    # Wrap the uuid's 16 bytes as a Memory and fill with random data
    mem = unsafe_wrap(Memory{UInt8}, _uuid_bytes_ptr(uuid), 16; own = false)
    buf = Ref(ByteBuffer(mem, Csize_t(0)))
    return device_random_buffer(buf)
end

function uuid_init(u::Base.RefValue{uuid})
    return uuid_init(Base.unsafe_convert(Ptr{uuid}, u))
end

function uuid_init_from_str(uuid::Ptr{uuid}, uuid_str::Ptr{ByteCursor})
    precondition(uuid != C_NULL)
    precondition(uuid_str != C_NULL)
    str_val = unsafe_load(uuid_str)
    if str_val.len < UUID_STR_LEN - 1
        return raise_error(ERROR_INVALID_BUFFER_SIZE)
    end
    hex_digits = Vector{UInt8}(undef, 32)
    idx = 1
    for pos in 0:35
        ch = unsafe_load(str_val.ptr + pos)
        if pos == 8 || pos == 13 || pos == 18 || pos == 23
            if ch != UInt8('-')
                return raise_error(ERROR_MALFORMED_INPUT_STRING)
            end
        else
            if idx > 32
                return raise_error(ERROR_MALFORMED_INPUT_STRING)
            end
            hex_digits[idx] = ch
            idx += 1
        end
    end
    if idx != 33
        return raise_error(ERROR_MALFORMED_INPUT_STRING)
    end
    bytes = Vector{UInt8}(undef, 16)
    for i in 1:16
        high_val = Ref{UInt8}(0)
        low_val = Ref{UInt8}(0)
        if _hex_decode_char_to_int(hex_digits[2 * i - 1], high_val) != OP_SUCCESS ||
                _hex_decode_char_to_int(hex_digits[2 * i], low_val) != OP_SUCCESS
            return raise_error(ERROR_MALFORMED_INPUT_STRING)
        end
        bytes[i] = (high_val[] << 4) | low_val[]
    end
    uuid_tuple = ntuple(i -> bytes[i], 16)
    unsafe_store!(uuid, uuid(uuid_tuple))
    return OP_SUCCESS
end

function uuid_init_from_str(u::Base.RefValue{uuid}, uuid_str::Base.RefValue{ByteCursor})
    return uuid_init_from_str(
        Base.unsafe_convert(Ptr{uuid}, u),
        Base.unsafe_convert(Ptr{ByteCursor}, uuid_str),
    )
end

@inline function _uuid_write_hex(dst::Ptr{UInt8}, byte::UInt8)
    unsafe_store!(dst, _hex_digits[Int((byte >> 4) & 0x0f) + 1])
    unsafe_store!(dst + 1, _hex_digits[Int(byte & 0x0f) + 1])
    return nothing
end

function _uuid_to_str(uuid::Ptr{uuid}, output::Ptr{ByteBuffer}, padded_len::Integer, compact::Bool)
    precondition(uuid != C_NULL)
    precondition(output != C_NULL)
    out_val = unsafe_load(output)
    space_remaining = out_val.capacity - out_val.len
    if space_remaining < padded_len
        return raise_error(ERROR_SHORT_BUFFER)
    end
    dst = pointer(out_val.mem) + out_val.len
    bytes_ptr = _uuid_bytes_ptr(uuid)
    idx = 0
    for i in 0:15
        _uuid_write_hex(dst + idx, unsafe_load(bytes_ptr + i))
        idx += 2
        if !compact && (i == 3 || i == 5 || i == 7 || i == 9)
            unsafe_store!(dst + idx, UInt8('-'))
            idx += 1
        end
    end
    unsafe_store!(dst + idx, 0x00)
    unsafe_store!(output, ByteBuffer(out_val.mem, out_val.len + (padded_len - 1)))
    return OP_SUCCESS
end

function uuid_to_str(uuid::Ptr{uuid}, output::Ptr{ByteBuffer})
    return _uuid_to_str(uuid, output, UUID_STR_LEN, false)
end

function uuid_to_str(u::Base.RefValue{uuid}, output::Base.RefValue{<:ByteBuffer})
    return uuid_to_str(
        Base.unsafe_convert(Ptr{uuid}, u),
        Base.unsafe_convert(Ptr{ByteBuffer}, output),
    )
end
