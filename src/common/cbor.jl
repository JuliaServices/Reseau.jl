@enumx CborType::UInt8 begin
    UNKNOWN = 0
    UINT
    NEGINT
    FLOAT
    BYTES
    TEXT
    ARRAY_START
    MAP_START
    TAG
    BOOL
    NULL
    UNDEFINED
    BREAK
    INDEF_BYTES_START
    INDEF_TEXT_START
    INDEF_ARRAY_START
    INDEF_MAP_START
end

const cbor_type = CborType.T

const CBOR_TAG_STANDARD_TIME = UInt64(0)
const CBOR_TAG_EPOCH_TIME = UInt64(1)
const CBOR_TAG_UNSIGNED_BIGNUM = UInt64(2)
const CBOR_TAG_NEGATIVE_BIGNUM = UInt64(3)
const CBOR_TAG_DECIMAL_FRACTION = UInt64(4)

mutable struct cbor_encoder
    encoded_buf::ByteBuffer
end

struct cbor_decoder_context
    type::cbor_type
    unsigned_int_val::UInt64
    negative_int_val::UInt64
    float_val::Float64
    tag_val::UInt64
    boolean_val::Bool
    bytes_val::ByteCursor
    text_val::ByteCursor
    map_start::UInt64
    array_start::UInt64
end

mutable struct cbor_decoder
    src::ByteCursor
    cached_context::cbor_decoder_context
    error_code::Int
end

@inline function _cbor_context_zero()
    return cbor_decoder_context(
        CborType.UNKNOWN,
        0,
        0,
        0.0,
        0,
        false,
        null_cursor(),
        null_cursor(),
        0,
        0,
    )
end

@inline function _cbor_decoder_error(decoder::cbor_decoder)
    return decoder.error_code
end

@inline function _cbor_decoder_set_error!(decoder::cbor_decoder, err::Int)
    decoder.error_code = err
    return raise_error(err)
end

const _CBOR_MAJOR_TYPE_UINT = UInt8(0)
const _CBOR_MAJOR_TYPE_NEGINT = UInt8(1)
const _CBOR_MAJOR_TYPE_BYTES = UInt8(2)
const _CBOR_MAJOR_TYPE_TEXT = UInt8(3)
const _CBOR_MAJOR_TYPE_ARRAY = UInt8(4)
const _CBOR_MAJOR_TYPE_MAP = UInt8(5)
const _CBOR_MAJOR_TYPE_TAG = UInt8(6)
const _CBOR_MAJOR_TYPE_SIMPLE = UInt8(7)

const _CBOR_ADDITIONAL_INDEF = UInt8(31)
const _CBOR_SIMPLE_VAL_FALSE = UInt8(20)
const _CBOR_SIMPLE_VAL_TRUE = UInt8(21)
const _CBOR_SIMPLE_VAL_NULL = UInt8(22)
const _CBOR_SIMPLE_VAL_UNDEFINED = UInt8(23)
const _CBOR_SIMPLE_VAL_BREAK = UInt8(31)

@inline function _cbor_uint_width(value::UInt64)
    if value <= 23
        return 0
    elseif value <= typemax(UInt8)
        return 1
    elseif value <= typemax(UInt16)
        return 2
    elseif value <= typemax(UInt32)
        return 4
    end
    return 8
end

@inline function _cbor_write_u8!(buf_ptr, value::UInt8)
    ref = Ref{UInt8}(value)
    ok = byte_buf_write(buf_ptr, Base.unsafe_convert(Ptr{UInt8}, ref), 1)
    fatal_assert_bool(ok, "byte_buf_write", "<unknown>", 0)
    return nothing
end

@inline function _cbor_encoder_reserve!(encoder::cbor_encoder, additional_len::Integer)
    buf_ref = Ref(encoder.encoded_buf)
    result = byte_buf_reserve_smart_relative(buf_ref, additional_len)
    encoder.encoded_buf = buf_ref[]
    fatal_assert_bool(result == OP_SUCCESS, "result == OP_SUCCESS", "<unknown>", 0)
    return nothing
end

function _cbor_encode_type_value!(buf_ptr, major::UInt8, value::UInt64)
    if value <= 23
        _cbor_write_u8!(buf_ptr, UInt8((major << 5) | UInt8(value)))
        return nothing
    end
    if value <= typemax(UInt8)
        _cbor_write_u8!(buf_ptr, UInt8((major << 5) | 24))
        _cbor_write_u8!(buf_ptr, UInt8(value))
        return nothing
    end
    if value <= typemax(UInt16)
        _cbor_write_u8!(buf_ptr, UInt8((major << 5) | 25))
        ok = byte_buf_write_be16(buf_ptr, UInt16(value))
        fatal_assert_bool(ok, "byte_buf_write_be16", "<unknown>", 0)
        return nothing
    end
    if value <= typemax(UInt32)
        _cbor_write_u8!(buf_ptr, UInt8((major << 5) | 26))
        ok = byte_buf_write_be32(buf_ptr, UInt32(value))
        fatal_assert_bool(ok, "byte_buf_write_be32", "<unknown>", 0)
        return nothing
    end
    _cbor_write_u8!(buf_ptr, UInt8((major << 5) | 27))
    ok = byte_buf_write_be64(buf_ptr, UInt64(value))
    fatal_assert_bool(ok, "byte_buf_write_be64", "<unknown>", 0)
    return nothing
end

function cbor_encoder_new()
    buf_ref = Ref{ByteBuffer}()
    if byte_buf_init(buf_ref, 256) != OP_SUCCESS
        return nothing
    end
    return cbor_encoder(buf_ref[])
end

function cbor_encoder_destroy(encoder::Union{cbor_encoder, Nothing})
    encoder === nothing && return nothing
    buf_ref = Ref(encoder.encoded_buf)
    byte_buf_clean_up(buf_ref)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_get_encoded_data(encoder::Union{cbor_encoder, Nothing})
    encoder === nothing && return null_cursor()
    buf_ref = Ref(encoder.encoded_buf)
    return byte_cursor_from_buf(buf_ref)
end

function cbor_encoder_reset(encoder::Union{cbor_encoder, Nothing})
    encoder === nothing && return nothing
    buf_ref = Ref(encoder.encoded_buf)
    byte_buf_reset(buf_ref, false)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_uint(encoder::cbor_encoder, value::UInt64)
    _cbor_encoder_reserve!(encoder, 1 + _cbor_uint_width(value))
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_UINT, value)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_negint(encoder::cbor_encoder, value::UInt64)
    _cbor_encoder_reserve!(encoder, 1 + _cbor_uint_width(value))
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_NEGINT, value)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_single_float(encoder::cbor_encoder, value::Float32)
    _cbor_encoder_reserve!(encoder, 5)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | 26))
    ok = byte_buf_write_float_be32(buf_ref, value)
    encoder.encoded_buf = buf_ref[]
    fatal_assert_bool(ok, "byte_buf_write_float_be32", "<unknown>", 0)
    return nothing
end

function cbor_encoder_write_float(encoder::cbor_encoder, value::Float64)
    if !isfinite(value)
        cbor_encoder_write_single_float(encoder, Float32(value))
        return nothing
    end
    if value <= Float64(typemax(Int64)) && value >= Float64(typemin(Int64))
        int_value = trunc(Int64, value)
        if value == Float64(int_value)
            if int_value < 0
                cbor_encoder_write_negint(encoder, UInt64(-1 - int_value))
            else
                cbor_encoder_write_uint(encoder, UInt64(int_value))
            end
            return nothing
        end
    end
    if value <= floatmax(Float32) && value >= -floatmax(Float32)
        float_value = Float32(value)
        if value == Float64(float_value)
            cbor_encoder_write_single_float(encoder, float_value)
            return nothing
        end
    end
    _cbor_encoder_reserve!(encoder, 9)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | 27))
    ok = byte_buf_write_float_be64(buf_ref, value)
    encoder.encoded_buf = buf_ref[]
    fatal_assert_bool(ok, "byte_buf_write_float_be64", "<unknown>", 0)
    return nothing
end

function cbor_encoder_write_bytes(encoder::cbor_encoder, from::ByteCursor)
    length = UInt64(from.len)
    reserve = Csize_t(1 + _cbor_uint_width(length)) + from.len
    _cbor_encoder_reserve!(encoder, reserve)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_BYTES, length)
    if from.len > 0
        ok = byte_buf_append(buf_ref, Ref(from))
        fatal_assert_bool(ok == OP_SUCCESS, "byte_buf_append", "<unknown>", 0)
    end
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_text(encoder::cbor_encoder, from::ByteCursor)
    length = UInt64(from.len)
    reserve = Csize_t(1 + _cbor_uint_width(length)) + from.len
    _cbor_encoder_reserve!(encoder, reserve)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_TEXT, length)
    if from.len > 0
        ok = byte_buf_append(buf_ref, Ref(from))
        fatal_assert_bool(ok == OP_SUCCESS, "byte_buf_append", "<unknown>", 0)
    end
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_array_start(encoder::cbor_encoder, number_entries::UInt64)
    _cbor_encoder_reserve!(encoder, 1 + _cbor_uint_width(number_entries))
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_ARRAY, number_entries)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_map_start(encoder::cbor_encoder, number_entries::UInt64)
    _cbor_encoder_reserve!(encoder, 1 + _cbor_uint_width(number_entries))
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_MAP, number_entries)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_tag(encoder::cbor_encoder, tag_number::UInt64)
    _cbor_encoder_reserve!(encoder, 1 + _cbor_uint_width(tag_number))
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_encode_type_value!(buf_ref, _CBOR_MAJOR_TYPE_TAG, tag_number)
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_null(encoder::cbor_encoder)
    _cbor_encoder_reserve!(encoder, 1)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | _CBOR_SIMPLE_VAL_NULL))
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_undefined(encoder::cbor_encoder)
    _cbor_encoder_reserve!(encoder, 1)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | _CBOR_SIMPLE_VAL_UNDEFINED))
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_bool(encoder::cbor_encoder, value::Bool)
    _cbor_encoder_reserve!(encoder, 1)
    buf_ref = Ref(encoder.encoded_buf)
    ctrl = value ? _CBOR_SIMPLE_VAL_TRUE : _CBOR_SIMPLE_VAL_FALSE
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | ctrl))
    encoder.encoded_buf = buf_ref[]
    return nothing
end

@inline function _cbor_encoder_write_type_only(encoder::cbor_encoder, major::UInt8)
    _cbor_encoder_reserve!(encoder, 1)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((major << 5) | _CBOR_ADDITIONAL_INDEF))
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_encoder_write_indef_bytes_start(encoder::cbor_encoder)
    _cbor_encoder_write_type_only(encoder, _CBOR_MAJOR_TYPE_BYTES)
    return nothing
end

function cbor_encoder_write_indef_text_start(encoder::cbor_encoder)
    _cbor_encoder_write_type_only(encoder, _CBOR_MAJOR_TYPE_TEXT)
    return nothing
end

function cbor_encoder_write_indef_array_start(encoder::cbor_encoder)
    _cbor_encoder_write_type_only(encoder, _CBOR_MAJOR_TYPE_ARRAY)
    return nothing
end

function cbor_encoder_write_indef_map_start(encoder::cbor_encoder)
    _cbor_encoder_write_type_only(encoder, _CBOR_MAJOR_TYPE_MAP)
    return nothing
end

function cbor_encoder_write_break(encoder::cbor_encoder)
    _cbor_encoder_reserve!(encoder, 1)
    buf_ref = Ref(encoder.encoded_buf)
    _cbor_write_u8!(buf_ref, UInt8((_CBOR_MAJOR_TYPE_SIMPLE << 5) | _CBOR_SIMPLE_VAL_BREAK))
    encoder.encoded_buf = buf_ref[]
    return nothing
end

function cbor_decoder_new(src::ByteCursor)
    return cbor_decoder(src, _cbor_context_zero(), ERROR_SUCCESS)
end

function cbor_decoder_destroy(decoder::Union{cbor_decoder, Nothing})
    # No-op: Julia GC handles memory
    return nothing
end

function cbor_decoder_get_remaining_length(decoder::Union{cbor_decoder, Nothing})
    decoder === nothing && return Csize_t(0)
    return decoder.src.len
end

function cbor_decoder_reset_src(decoder::Union{cbor_decoder, Nothing}, src::ByteCursor)
    decoder === nothing && return nothing
    decoder.src = src
    decoder.cached_context = _cbor_context_zero()
    decoder.error_code = ERROR_SUCCESS
    return nothing
end

@inline function _cbor_read_uint(src_ref::Base.RefValue{ByteCursor}, additional::UInt8, out::Base.RefValue{UInt64})
    if additional < 24
        out[] = UInt64(additional)
        return true
    elseif additional == 24
        tmp = Ref{UInt8}(0)
        if !byte_cursor_read_u8(src_ref, tmp)
            return false
        end
        out[] = UInt64(tmp[])
        return true
    elseif additional == 25
        tmp = Ref{UInt16}(0)
        if !byte_cursor_read_be16(src_ref, tmp)
            return false
        end
        out[] = UInt64(tmp[])
        return true
    elseif additional == 26
        tmp = Ref{UInt32}(0)
        if !byte_cursor_read_be32(src_ref, tmp)
            return false
        end
        out[] = UInt64(tmp[])
        return true
    elseif additional == 27
        tmp = Ref{UInt64}(0)
        if !byte_cursor_read_be64(src_ref, tmp)
            return false
        end
        out[] = tmp[]
        return true
    end
    return false
end

@inline function _cbor_decode_half(value::UInt16)
    sign = (value >> 15) & 0x01
    exp = (value >> 10) & 0x1f
    frac = value & 0x03ff
    if exp == 0
        if frac == 0
            result = 0.0
        else
            result = ldexp(Float64(frac), -24)
        end
    elseif exp == 0x1f
        result = frac == 0 ? Inf : NaN
    else
        result = ldexp(1.0 + Float64(frac) / 1024.0, Int(exp) - 15)
    end
    return sign == 1 ? -result : result
end

function _cbor_decode_next_element(decoder::cbor_decoder)
    if _cbor_decoder_error(decoder) != ERROR_SUCCESS
        return _cbor_decoder_set_error!(decoder, _cbor_decoder_error(decoder))
    end
    if decoder.cached_context.type != CborType.UNKNOWN
        return OP_SUCCESS
    end
    src_ref = Ref(decoder.src)
    initial = Ref{UInt8}(0)
    if !byte_cursor_read_u8(src_ref, initial)
        return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
    end
    major = UInt8(initial[] >> 5)
    additional = UInt8(initial[] & 0x1f)
    value_ref = Ref{UInt64}(0)
    if major == _CBOR_MAJOR_TYPE_UINT
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.UINT, value_ref[], 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_NEGINT
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.NEGINT, 0, value_ref[], 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_BYTES
        if additional == _CBOR_ADDITIONAL_INDEF
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.INDEF_BYTES_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        end
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        if value_ref[] > typemax(Csize_t)
            return _cbor_decoder_set_error!(decoder, ERROR_OVERFLOW_DETECTED)
        end
        len = Csize_t(value_ref[])
        slice = byte_cursor_advance(src_ref, len)
        if slice.len != len
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.BYTES, 0, 0, 0.0, 0, false, slice, null_cursor(), 0, 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_TEXT
        if additional == _CBOR_ADDITIONAL_INDEF
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.INDEF_TEXT_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        end
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        if value_ref[] > typemax(Csize_t)
            return _cbor_decoder_set_error!(decoder, ERROR_OVERFLOW_DETECTED)
        end
        len = Csize_t(value_ref[])
        slice = byte_cursor_advance(src_ref, len)
        if slice.len != len
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.TEXT, 0, 0, 0.0, 0, false, null_cursor(), slice, 0, 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_ARRAY
        if additional == _CBOR_ADDITIONAL_INDEF
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.INDEF_ARRAY_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        end
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.ARRAY_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, value_ref[],
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_MAP
        if additional == _CBOR_ADDITIONAL_INDEF
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.INDEF_MAP_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        end
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.MAP_START, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), value_ref[], 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_TAG
        if !_cbor_read_uint(src_ref, additional, value_ref)
            return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
        end
        decoder.src = src_ref[]
        decoder.cached_context = cbor_decoder_context(
            CborType.TAG, 0, 0, 0.0, value_ref[], false, null_cursor(), null_cursor(), 0, 0,
        )
        return OP_SUCCESS
    elseif major == _CBOR_MAJOR_TYPE_SIMPLE
        if additional == _CBOR_SIMPLE_VAL_FALSE
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.BOOL, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == _CBOR_SIMPLE_VAL_TRUE
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.BOOL, 0, 0, 0.0, 0, true, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == _CBOR_SIMPLE_VAL_NULL
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.NULL, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == _CBOR_SIMPLE_VAL_UNDEFINED
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.UNDEFINED, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == _CBOR_SIMPLE_VAL_BREAK
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.BREAK, 0, 0, 0.0, 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == 25
            tmp = Ref{UInt16}(0)
            if !byte_cursor_read_be16(src_ref, tmp)
                return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
            end
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.FLOAT, 0, 0, _cbor_decode_half(tmp[]), 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == 26
            tmp = Ref{Float32}(0.0f0)
            if !byte_cursor_read_float_be32(src_ref, tmp)
                return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
            end
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.FLOAT, 0, 0, Float64(tmp[]), 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        elseif additional == 27
            tmp = Ref{Float64}(0.0)
            if !byte_cursor_read_float_be64(src_ref, tmp)
                return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
            end
            decoder.src = src_ref[]
            decoder.cached_context = cbor_decoder_context(
                CborType.FLOAT, 0, 0, tmp[], 0, false, null_cursor(), null_cursor(), 0, 0,
            )
            return OP_SUCCESS
        end
        return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
    end
    return _cbor_decoder_set_error!(decoder, ERROR_INVALID_CBOR)
end

function cbor_decoder_peek_type(decoder::cbor_decoder, out_type::Base.RefValue{cbor_type})
    if _cbor_decoder_error(decoder) != ERROR_SUCCESS
        return _cbor_decoder_set_error!(decoder, _cbor_decoder_error(decoder))
    end
    if decoder.cached_context.type == CborType.UNKNOWN
        if _cbor_decode_next_element(decoder) != OP_SUCCESS
            return OP_ERR
        end
    end
    out_type[] = decoder.cached_context.type
    return OP_SUCCESS
end

@inline function _cbor_decoder_pop!(decoder::cbor_decoder, expected::cbor_type)
    if _cbor_decoder_error(decoder) != ERROR_SUCCESS
        return OP_ERR, _cbor_context_zero()
    end
    if decoder.cached_context.type == CborType.UNKNOWN
        if _cbor_decode_next_element(decoder) != OP_SUCCESS
            return OP_ERR, _cbor_context_zero()
        end
    end
    if decoder.cached_context.type != expected
        _cbor_decoder_set_error!(decoder, ERROR_CBOR_UNEXPECTED_TYPE)
        return OP_ERR, _cbor_context_zero()
    end
    context_val = decoder.cached_context
    decoder.cached_context = _cbor_context_zero()
    return OP_SUCCESS, context_val
end

function cbor_decoder_pop_next_unsigned_int_val(decoder::cbor_decoder, out::Base.RefValue{UInt64})
    result, context = _cbor_decoder_pop!(decoder, CborType.UINT)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.unsigned_int_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_negative_int_val(decoder::cbor_decoder, out::Base.RefValue{UInt64})
    result, context = _cbor_decoder_pop!(decoder, CborType.NEGINT)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.negative_int_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_float_val(decoder::cbor_decoder, out::Base.RefValue{Float64})
    result, context = _cbor_decoder_pop!(decoder, CborType.FLOAT)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.float_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_boolean_val(decoder::cbor_decoder, out::Base.RefValue{Bool})
    result, context = _cbor_decoder_pop!(decoder, CborType.BOOL)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.boolean_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_text_val(decoder::cbor_decoder, out::Base.RefValue{ByteCursor})
    result, context = _cbor_decoder_pop!(decoder, CborType.TEXT)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.text_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_bytes_val(decoder::cbor_decoder, out::Base.RefValue{ByteCursor})
    result, context = _cbor_decoder_pop!(decoder, CborType.BYTES)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.bytes_val
    return OP_SUCCESS
end

function cbor_decoder_pop_next_map_start(decoder::cbor_decoder, out::Base.RefValue{UInt64})
    result, context = _cbor_decoder_pop!(decoder, CborType.MAP_START)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.map_start
    return OP_SUCCESS
end

function cbor_decoder_pop_next_array_start(decoder::cbor_decoder, out::Base.RefValue{UInt64})
    result, context = _cbor_decoder_pop!(decoder, CborType.ARRAY_START)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.array_start
    return OP_SUCCESS
end

function cbor_decoder_pop_next_tag_val(decoder::cbor_decoder, out::Base.RefValue{UInt64})
    result, context = _cbor_decoder_pop!(decoder, CborType.TAG)
    if result != OP_SUCCESS
        return OP_ERR
    end
    out[] = context.tag_val
    return OP_SUCCESS
end

function cbor_decoder_consume_next_whole_data_item(decoder::cbor_decoder)
    if _cbor_decoder_error(decoder) != ERROR_SUCCESS
        return _cbor_decoder_set_error!(decoder, _cbor_decoder_error(decoder))
    end
    if decoder.cached_context.type == CborType.UNKNOWN
        if _cbor_decode_next_element(decoder) != OP_SUCCESS
            return OP_ERR
        end
    end
    context_val = decoder.cached_context
    if context_val.type == CborType.TAG
        decoder.cached_context = _cbor_context_zero()
        return cbor_decoder_consume_next_whole_data_item(decoder)
    elseif context_val.type == CborType.MAP_START
        count = context_val.map_start
        decoder.cached_context = _cbor_context_zero()
        for _ in UInt64(1):count
            if cbor_decoder_consume_next_whole_data_item(decoder) != OP_SUCCESS
                return OP_ERR
            end
            if cbor_decoder_consume_next_whole_data_item(decoder) != OP_SUCCESS
                return OP_ERR
            end
        end
    elseif context_val.type == CborType.ARRAY_START
        count = context_val.array_start
        decoder.cached_context = _cbor_context_zero()
        for _ in UInt64(1):count
            if cbor_decoder_consume_next_whole_data_item(decoder) != OP_SUCCESS
                return OP_ERR
            end
        end
    elseif context_val.type == CborType.INDEF_BYTES_START ||
            context_val.type == CborType.INDEF_TEXT_START ||
            context_val.type == CborType.INDEF_ARRAY_START ||
            context_val.type == CborType.INDEF_MAP_START
        decoder.cached_context = _cbor_context_zero()
        next_type = Ref{cbor_type}(CborType.UNKNOWN)
        if cbor_decoder_peek_type(decoder, next_type) != OP_SUCCESS
            return OP_ERR
        end
        while next_type[] != CborType.BREAK
            if cbor_decoder_consume_next_whole_data_item(decoder) != OP_SUCCESS
                return OP_ERR
            end
            if cbor_decoder_peek_type(decoder, next_type) != OP_SUCCESS
                return OP_ERR
            end
        end
    end
    decoder.cached_context = _cbor_context_zero()
    return OP_SUCCESS
end

function cbor_decoder_consume_next_single_element(decoder::cbor_decoder)
    out_type = Ref{cbor_type}(CborType.UNKNOWN)
    if cbor_decoder_peek_type(decoder, out_type) != OP_SUCCESS
        return OP_ERR
    end
    decoder.cached_context = _cbor_context_zero()
    return OP_SUCCESS
end
