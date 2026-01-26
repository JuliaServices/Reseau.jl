const _HEX_CHARS = collect(codeunits("0123456789abcdef"))

const _BASE64_SENTINEL_VALUE = UInt8(0xff)
const _BASE64_ENCODING_TABLE = collect(codeunits("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
const _BASE64_URL_ENCODING_TABLE = collect(codeunits("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"))

const _BASE64_DECODING_TABLE = let tbl = fill(UInt8(0xdd), 256)
    tbl[1] = UInt8(64)
    for i in 0:25
        tbl[Int(UInt8('A') + i) + 1] = UInt8(i)
        tbl[Int(UInt8('a') + i) + 1] = UInt8(26 + i)
    end
    for i in 0:9
        tbl[Int(UInt8('0') + i) + 1] = UInt8(52 + i)
    end
    tbl[Int(UInt8('+')) + 1] = UInt8(62)
    tbl[Int(UInt8('-')) + 1] = UInt8(62)
    tbl[Int(UInt8('/')) + 1] = UInt8(63)
    tbl[Int(UInt8('_')) + 1] = UInt8(63)
    tbl[Int(UInt8('=')) + 1] = _BASE64_SENTINEL_VALUE
    tbl
end

function hex_compute_encoded_len(to_encode_len::Integer)
    temp = Csize_t(to_encode_len) << 1
    if temp < Csize_t(to_encode_len)
        raise_error(ERROR_OVERFLOW_DETECTED)
        return Csize_t(0)
    end
    return temp
end

function hex_encode(to_encode::ByteCursor, output::ByteBuffer)
    encoded_len = hex_compute_encoded_len(to_encode.len)
    if encoded_len == 0 && to_encode.len > 0
        return OP_ERR
    end
    needed = Ref{Csize_t}(0)
    if add_size_checked(output.len, encoded_len, needed) != OP_SUCCESS
        return OP_ERR
    end
    if capacity(output) < needed[]
        return raise_error(ERROR_SHORT_BUFFER)
    end
    written = Int(output.len) + 1
    len = Int(to_encode.len)
    @inbounds for i in 1:len
        byte = memoryref(to_encode.ptr, i)[]
        output.mem[written] = _HEX_CHARS[(byte >> 4) + 1]
        written += 1
        output.mem[written] = _HEX_CHARS[(byte & 0x0f) + 1]
        written += 1
    end
    output.len += encoded_len
    return OP_SUCCESS
end

function hex_encode_append_dynamic(to_encode::ByteCursor, output::Ref{<:ByteBuffer})
    encoded_len_ref = Ref{Csize_t}(0)
    if add_size_checked(to_encode.len, to_encode.len, encoded_len_ref) != OP_SUCCESS
        return OP_ERR
    end
    encoded_len = encoded_len_ref[]
    if byte_buf_reserve_relative(output, encoded_len) != OP_SUCCESS
        return OP_ERR
    end
    written = Int(output[].len) + 1
    len = Int(to_encode.len)
    @inbounds for i in 1:len
        byte = memoryref(to_encode.ptr, i)[]
        output[].mem[written] = _HEX_CHARS[(byte >> 4) + 1]
        written += 1
        output[].mem[written] = _HEX_CHARS[(byte & 0x0f) + 1]
        written += 1
    end
    output[].len += encoded_len
    return OP_SUCCESS
end

@inline function _hex_decode_char_to_int(character::UInt8)
    if character >= UInt8('a') && character <= UInt8('f')
        return (OP_SUCCESS, UInt8(10 + (character - UInt8('a'))))
    end
    if character >= UInt8('A') && character <= UInt8('F')
        return (OP_SUCCESS, UInt8(10 + (character - UInt8('A'))))
    end
    if character >= UInt8('0') && character <= UInt8('9')
        return (OP_SUCCESS, UInt8(character - UInt8('0')))
    end
    return (OP_ERR, UInt8(0))
end

function hex_compute_decoded_len(to_decode_len::Integer)
    temp = Csize_t(to_decode_len) + 1
    if temp < Csize_t(to_decode_len)
        raise_error(ERROR_OVERFLOW_DETECTED)
        return Csize_t(0)
    end
    return temp >> 1
end

function hex_decode(to_decode::ByteCursor, output::ByteBuffer)
    decoded_len = hex_compute_decoded_len(to_decode.len)
    if decoded_len == 0 && to_decode.len > 1
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    needed = Ref{Csize_t}(0)
    if add_size_checked(output.len, decoded_len, needed) != OP_SUCCESS
        return OP_ERR
    end
    if capacity(output) < needed[]
        return raise_error(ERROR_SHORT_BUFFER)
    end
    written = Int(output.len) + 1
    i = 1
    len = Int(to_decode.len)
    if (len & 0x01) != 0
        i = 2
        status, low_value = _hex_decode_char_to_int(memoryref(to_decode.ptr, 1)[])
        if status != OP_SUCCESS
            return raise_error(ERROR_INVALID_HEX_STR)
        end
        output.mem[written] = low_value
        written += 1
    end
    while i <= len
        status1, high_value = _hex_decode_char_to_int(memoryref(to_decode.ptr, i)[])
        status2, low_value = _hex_decode_char_to_int(memoryref(to_decode.ptr, i + 1)[])
        if status1 != OP_SUCCESS || status2 != OP_SUCCESS
            return raise_error(ERROR_INVALID_HEX_STR)
        end
        value = UInt8(high_value << 4) | low_value
        output.mem[written] = value
        written += 1
        i += 2
    end
    output.len += decoded_len
    return OP_SUCCESS
end

function base64_compute_encoded_len(to_encode_len::Integer)
    tmp = Ref{Csize_t}(0)
    if add_size_checked(Csize_t(to_encode_len), Csize_t(2), tmp) != OP_SUCCESS
        return Csize_t(0)
    end
    tmp_val = tmp[] ÷ 3
    tmp2 = Ref{Csize_t}(0)
    if mul_size_checked(tmp_val, Csize_t(4), tmp2) != OP_SUCCESS
        return Csize_t(0)
    end
    return tmp2[]
end

function base64_url_compute_encoded_len(to_encode_len::Integer)
    tmp = Ref{Csize_t}(0)
    if mul_size_checked(Csize_t(to_encode_len), Csize_t(8), tmp) != OP_SUCCESS
        return Csize_t(0)
    end
    tmp2 = Ref{Csize_t}(0)
    if add_size_checked(tmp[], Csize_t(5), tmp2) != OP_SUCCESS
        return Csize_t(0)
    end
    return tmp2[] ÷ 6
end

@inline function _base64_is_padding(ch::UInt8)
    return ch == UInt8('=')
end

function base64_compute_decoded_len(to_decode::ByteCursor)
    trimmed = byte_cursor_right_trim_pred(to_decode, _base64_is_padding)
    len = trimmed.len
    if len == 0
        return Csize_t(0)
    end
    if (len % 4) == 1
        raise_error(ERROR_INVALID_BASE64_STR)
        return Csize_t(0)
    end
    tmp = Ref{Csize_t}(0)
    if mul_size_checked(len, Csize_t(3), tmp) != OP_SUCCESS
        return Csize_t(0)
    end
    return tmp[] >> 2
end

@inline function _base64_get_decoded_value(to_decode::UInt8, allow_sentinel::Bool)
    decode_value = _BASE64_DECODING_TABLE[Int(to_decode) + 1]
    if decode_value != UInt8(0xdd) && (decode_value != _BASE64_SENTINEL_VALUE || allow_sentinel)
        return (OP_SUCCESS, decode_value)
    end
    return (OP_ERR, UInt8(0))
end

function _base64_encode(to_encode::ByteCursor, output::ByteBuffer, do_url_safe_encoding::Bool)
    encoded_len = do_url_safe_encoding ?
        base64_url_compute_encoded_len(to_encode.len) :
        base64_compute_encoded_len(to_encode.len)

    # Check for overflow (encoded_len==0 but input length > 0)
    if encoded_len == 0 && to_encode.len > 0
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end

    needed_capacity = Ref{Csize_t}(0)
    if add_size_checked(output.len, encoded_len, needed_capacity) != OP_SUCCESS
        return OP_ERR
    end
    if capacity(output) < needed_capacity[]
        return raise_error(ERROR_SHORT_BUFFER)
    end

    # Safe to convert since we've checked for overflow
    if to_encode.len > typemax(Int)
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    buffer_length = Int(to_encode.len)
    block_count = (buffer_length + 2) ÷ 3
    remainder_count = buffer_length % 3
    str_index = Int(output.len) + 1
    encoding_table = do_url_safe_encoding ? _BASE64_URL_ENCODING_TABLE : _BASE64_ENCODING_TABLE

    if buffer_length > 0
        i = 1
        while i <= buffer_length
            block = UInt32(memoryref(to_encode.ptr, i)[])
            block <<= 8
            if i + 1 <= buffer_length
                block |= UInt32(memoryref(to_encode.ptr, i + 1)[])
            end
            block <<= 8
            if i + 2 <= buffer_length
                block |= UInt32(memoryref(to_encode.ptr, i + 2)[])
            end
            output.mem[str_index] = encoding_table[Int((block >> 18) & 0x3f) + 1]
            str_index += 1
            output.mem[str_index] = encoding_table[Int((block >> 12) & 0x3f) + 1]
            str_index += 1
            if i + 1 <= buffer_length
                output.mem[str_index] = encoding_table[Int((block >> 6) & 0x3f) + 1]
                str_index += 1
                if i + 2 <= buffer_length
                    output.mem[str_index] = encoding_table[Int(block & 0x3f) + 1]
                    str_index += 1
                end
            end
            i += 3
        end
    end

    if !do_url_safe_encoding && remainder_count > 0
        output.mem[Int(output.len) + block_count * 4] = UInt8('=')
        if remainder_count == 1
            output.mem[Int(output.len) + block_count * 4 - 1] = UInt8('=')
        end
    end

    output.len += encoded_len
    return OP_SUCCESS
end

function base64_encode(to_encode::ByteCursor, output::ByteBuffer)
    return _base64_encode(to_encode, output, false)
end

function base64_url_encode(to_encode::ByteCursor, output::ByteBuffer)
    return _base64_encode(to_encode, output, true)
end

function base64_decode(to_decode::ByteCursor, output::ByteBuffer)
    decoded_len = base64_compute_decoded_len(to_decode)
    if decoded_len == 0 && to_decode.len > 0
        # Check if it's an error case (invalid base64) or just empty input
        trimmed = byte_cursor_right_trim_pred(to_decode, _base64_is_padding)
        if trimmed.len > 0 && (trimmed.len % 4) == 1
            return OP_ERR
        end
    end
    needed = Ref{Csize_t}(0)
    if add_size_checked(output.len, decoded_len, needed) != OP_SUCCESS
        return OP_ERR
    end
    if capacity(output) < needed[]
        return raise_error(ERROR_SHORT_BUFFER)
    end

    len = Int(to_decode.len)
    block_count = (len + 3) ÷ 4
    remainder = len % 4
    string_index = 1
    written = Int(output.len) + 1

    if block_count > 1
        for i in 0:(block_count - 2)
            s1, v1 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index)[], false)
            s2, v2 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index + 1)[], false)
            s3, v3 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index + 2)[], false)
            s4, v4 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index + 3)[], false)
            if s1 != OP_SUCCESS || s2 != OP_SUCCESS || s3 != OP_SUCCESS || s4 != OP_SUCCESS
                return raise_error(ERROR_INVALID_BASE64_STR)
            end
            string_index += 4
            buffer_index = Int(output.len) + i * 3 + 1
            output.mem[buffer_index] = UInt8((v1 << 2) | ((v2 >> 4) & 0x03))
            output.mem[buffer_index + 1] = UInt8(((v2 << 4) & 0xf0) | ((v3 >> 2) & 0x0f))
            output.mem[buffer_index + 2] = UInt8(((v3 & 0x03) << 6) | v4)
        end
    end

    if block_count > 0
        buffer_index = Int(output.len) + (block_count - 1) * 3 + 1
        s1, v1 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index)[], false)
        s2, v2 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index + 1)[], false)
        if s1 != OP_SUCCESS || s2 != OP_SUCCESS
            return raise_error(ERROR_INVALID_BASE64_STR)
        end
        string_index += 2
        v3 = _BASE64_SENTINEL_VALUE
        v4 = _BASE64_SENTINEL_VALUE
        if (remainder == 3 || remainder == 0) && string_index <= len
            s3, v3 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index)[], true)
            if s3 != OP_SUCCESS
                return raise_error(ERROR_INVALID_BASE64_STR)
            end
        end
        if remainder == 0 && string_index + 1 <= len
            string_index += 1
            s4, v4 = _base64_get_decoded_value(memoryref(to_decode.ptr, string_index)[], true)
            if s4 != OP_SUCCESS
                return raise_error(ERROR_INVALID_BASE64_STR)
            end
        end
        output.mem[buffer_index] = UInt8((v1 << 2) | ((v2 >> 4) & 0x03))
        if v3 != _BASE64_SENTINEL_VALUE
            output.mem[buffer_index + 1] = UInt8(((v2 << 4) & 0xf0) | ((v3 >> 2) & 0x0f))
            if v4 != _BASE64_SENTINEL_VALUE
                output.mem[buffer_index + 2] = UInt8(((v3 & 0x03) << 6) | v4)
            end
        end
    end

    output.len += decoded_len
    return OP_SUCCESS
end

# Memory-based write/read functions for network byte order (big-endian)
# Note: Manual byte extraction handles the byte order, so NO hton/ntoh needed
function write_u64(value::UInt64, mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        mem[offset] = UInt8((value >> 56) & 0xff)
        mem[offset + 1] = UInt8((value >> 48) & 0xff)
        mem[offset + 2] = UInt8((value >> 40) & 0xff)
        mem[offset + 3] = UInt8((value >> 32) & 0xff)
        mem[offset + 4] = UInt8((value >> 24) & 0xff)
        mem[offset + 5] = UInt8((value >> 16) & 0xff)
        mem[offset + 6] = UInt8((value >> 8) & 0xff)
        mem[offset + 7] = UInt8(value & 0xff)
    end
    return nothing
end

function read_u64(mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        val = UInt64(mem[offset]) << 56
        val |= UInt64(mem[offset + 1]) << 48
        val |= UInt64(mem[offset + 2]) << 40
        val |= UInt64(mem[offset + 3]) << 32
        val |= UInt64(mem[offset + 4]) << 24
        val |= UInt64(mem[offset + 5]) << 16
        val |= UInt64(mem[offset + 6]) << 8
        val |= UInt64(mem[offset + 7])
    end
    return val
end

function write_u32(value::UInt32, mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        mem[offset] = UInt8((value >> 24) & 0xff)
        mem[offset + 1] = UInt8((value >> 16) & 0xff)
        mem[offset + 2] = UInt8((value >> 8) & 0xff)
        mem[offset + 3] = UInt8(value & 0xff)
    end
    return nothing
end

function read_u32(mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        val = UInt32(mem[offset]) << 24
        val |= UInt32(mem[offset + 1]) << 16
        val |= UInt32(mem[offset + 2]) << 8
        val |= UInt32(mem[offset + 3])
    end
    return val
end

function write_u24(value::UInt32, mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        mem[offset] = UInt8((value >> 16) & 0xff)
        mem[offset + 1] = UInt8((value >> 8) & 0xff)
        mem[offset + 2] = UInt8(value & 0xff)
    end
    return nothing
end

function read_u24(mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        val = UInt32(mem[offset]) << 16
        val |= UInt32(mem[offset + 1]) << 8
        val |= UInt32(mem[offset + 2])
    end
    return val
end

function write_u16(value::UInt16, mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        mem[offset] = UInt8((value >> 8) & 0xff)
        mem[offset + 1] = UInt8(value & 0xff)
    end
    return nothing
end

function read_u16(mem::Memory{UInt8}, offset::Int)
    @inbounds begin
        val = UInt16(mem[offset]) << 8
        val |= UInt16(mem[offset + 1])
    end
    return val
end

@enumx TextEncoding::UInt8 begin
    UNKNOWN = 0
    UTF8 = 1
    UTF16 = 2
    UTF32 = 3
    ASCII = 4
end

const text_encoding = TextEncoding.T

function text_detect_encoding(cursor::ByteCursor)
    size = cursor.len
    if size >= 3
        @inbounds begin
            b0 = memoryref(cursor.ptr, 1)[]
            b1 = memoryref(cursor.ptr, 2)[]
            b2 = memoryref(cursor.ptr, 3)[]
        end
        if b0 == 0xef && b1 == 0xbb && b2 == 0xbf
            return TextEncoding.UTF8
        end
    end
    if size >= 4
        @inbounds begin
            b0 = memoryref(cursor.ptr, 1)[]
            b1 = memoryref(cursor.ptr, 2)[]
            b2 = memoryref(cursor.ptr, 3)[]
            b3 = memoryref(cursor.ptr, 4)[]
        end
        if b0 == 0xff && b1 == 0xfe && b2 == 0x00 && b3 == 0x00
            return TextEncoding.UTF32
        end
        if b0 == 0x00 && b1 == 0x00 && b2 == 0xfe && b3 == 0xff
            return TextEncoding.UTF32
        end
    end
    if size >= 2
        @inbounds begin
            b0 = memoryref(cursor.ptr, 1)[]
            b1 = memoryref(cursor.ptr, 2)[]
        end
        if b0 == 0xff && b1 == 0xfe
            return TextEncoding.UTF16
        end
        if b0 == 0xfe && b1 == 0xff
            return TextEncoding.UTF16
        end
    end
    @inbounds for i in 1:Int(size)
        if (memoryref(cursor.ptr, i)[] & 0x80) != 0
            return TextEncoding.UNKNOWN
        end
    end
    return TextEncoding.ASCII
end

function text_is_utf8(cursor::ByteCursor)
    encoding = text_detect_encoding(cursor)
    return encoding == TextEncoding.UTF8 || encoding == TextEncoding.ASCII
end

struct Utf8DecoderOptions{F}
    on_codepoint::F
end

struct NoopCodepoint end

@inline (n::NoopCodepoint)(::UInt32) = OP_SUCCESS

Utf8DecoderOptions() = Utf8DecoderOptions(NoopCodepoint())

mutable struct Utf8Decoder{F}
    codepoint::UInt32
    min::UInt32
    remaining::UInt8
    on_codepoint::F
end

const utf8_decoder_options = Utf8DecoderOptions
const utf8_decoder = Utf8Decoder

function utf8_decoder_new(options::Utf8DecoderOptions{F} = Utf8DecoderOptions()) where {F}
    return Utf8Decoder{F}(0, 0, 0, options.on_codepoint)
end

utf8_decoder_destroy(::Utf8Decoder) = nothing

function utf8_decoder_reset(decoder::Utf8Decoder)
    decoder.codepoint = 0
    decoder.min = 0
    decoder.remaining = 0
    return nothing
end

@inline function _utf8_on_codepoint(decoder::Utf8Decoder, codepoint::UInt32)
    return decoder.on_codepoint(codepoint)
end

@inline function _utf8_store!(decoder::Utf8Decoder, codepoint::UInt32, min_val::UInt32, remaining::UInt8)
    decoder.codepoint = codepoint
    decoder.min = min_val
    decoder.remaining = remaining
    return nothing
end

function utf8_decoder_update(decoder::Utf8Decoder, bytes::ByteCursor)
    remaining = decoder.remaining
    codepoint = decoder.codepoint
    min_val = decoder.min
    len = Int(bytes.len)
    @inbounds for i in 1:len
        byte = memoryref(bytes.ptr, i)[]
        if remaining == 0
            if (byte & 0x80) == 0x00
                remaining = UInt8(0)
                codepoint = UInt32(byte)
                min_val = UInt32(0)
            elseif (byte & 0xe0) == 0xc0
                remaining = UInt8(1)
                codepoint = UInt32(byte & 0x1f)
                min_val = UInt32(0x80)
            elseif (byte & 0xf0) == 0xe0
                remaining = UInt8(2)
                codepoint = UInt32(byte & 0x0f)
                min_val = UInt32(0x0800)
            elseif (byte & 0xf8) == 0xf0
                remaining = UInt8(3)
                codepoint = UInt32(byte & 0x07)
                min_val = UInt32(0x00010000)
            else
                _utf8_store!(decoder, codepoint, min_val, remaining)
                return raise_error(ERROR_INVALID_UTF8)
            end
        else
            if (byte & 0xc0) != 0x80
                _utf8_store!(decoder, codepoint, min_val, remaining)
                return raise_error(ERROR_INVALID_UTF8)
            end
            codepoint = (codepoint << 6) | UInt32(byte & 0x3f)
            remaining = UInt8(remaining - 1)
            if remaining == 0
                if codepoint < min_val
                    _utf8_store!(decoder, codepoint, min_val, remaining)
                    return raise_error(ERROR_INVALID_UTF8)
                end
                if codepoint >= UInt32(0xd800) && codepoint <= UInt32(0xdfff)
                    _utf8_store!(decoder, codepoint, min_val, remaining)
                    return raise_error(ERROR_INVALID_UTF8)
                end
            end
        end
        if remaining == 0
            if _utf8_on_codepoint(decoder, codepoint) != OP_SUCCESS
                _utf8_store!(decoder, codepoint, min_val, remaining)
                return OP_ERR
            end
        end
    end
    _utf8_store!(decoder, codepoint, min_val, remaining)
    return OP_SUCCESS
end

function utf8_decoder_finalize(decoder::Utf8Decoder)
    valid = decoder.remaining == 0
    utf8_decoder_reset(decoder)
    if valid
        return OP_SUCCESS
    end
    return raise_error(ERROR_INVALID_UTF8)
end

function decode_utf8(bytes::ByteCursor, options::Utf8DecoderOptions = Utf8DecoderOptions())
    decoder = utf8_decoder_new(options)
    if utf8_decoder_update(decoder, bytes) != OP_SUCCESS
        return OP_ERR
    end
    if utf8_decoder_finalize(decoder) != OP_SUCCESS
        return OP_ERR
    end
    return OP_SUCCESS
end
