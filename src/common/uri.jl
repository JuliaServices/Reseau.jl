const URI_PORT_BUFFER_SIZE = 11

mutable struct Uri
    uri_str::ByteBuffer
    scheme::ByteCursor
    authority::ByteCursor
    userinfo::ByteCursor
    user::ByteCursor
    password::ByteCursor
    host_name::ByteCursor
    port::UInt32
    path::ByteCursor
    query_string::ByteCursor
    path_and_query::ByteCursor
end

function Uri()
    return Uri(
        null_buffer(),
        null_cursor(),
        null_cursor(),
        null_cursor(),
        null_cursor(),
        null_cursor(),
        null_cursor(),
        UInt32(0),
        null_cursor(),
        null_cursor(),
        null_cursor(),
    )
end

struct UriParam
    key::ByteCursor
    value::ByteCursor
end

Base.@kwdef struct UriBuilderOptions
    scheme::ByteCursor = null_cursor()
    path::ByteCursor = null_cursor()
    host_name::ByteCursor = null_cursor()
    port::UInt32 = 0
    query_params::Union{ArrayList{UriParam}, Nothing} = nothing
    query_string::ByteCursor = null_cursor()
end

const uri = Uri
const uri_param = UriParam
const uri_builder_options = UriBuilderOptions

# Create a ByteCursor slice from a ByteBuffer
# start and stop are 1-based indices into the buffer
@inline function _cursor_slice(buf::ByteBuffer, start::Int, stop::Int)
    if stop < start || start < 1
        return null_cursor()
    end
    len = stop - start + 1
    return ByteCursor(Csize_t(len), memoryref(buf.mem, start))
end

# Alternative form with length instead of stop index
@inline function _cursor_slice(buf::ByteBuffer, start::Int, len::Int, ::Val{:len})
    if len <= 0 || start < 1
        return null_cursor()
    end
    return ByteCursor(Csize_t(len), memoryref(buf.mem, start))
end

function _parse_port(port_str::AbstractString)
    isempty(port_str) && return UInt32(0), true
    all(Base.isdigit, port_str) || return UInt32(0), false
    value = tryparse(UInt64, port_str)
    value === nothing && return UInt32(0), false
    value > typemax(UInt32) && return UInt32(0), false
    return UInt32(value), true
end

function _parse_uri_from_buffer!(uri::Uri)
    buf = uri.uri_str
    total_len = Int(buf.len)
    if total_len == 0
        return OP_SUCCESS
    end

    # Convert Memory to String for parsing
    str = String(view(buf.mem, 1:total_len))
    n = lastindex(str)
    idx = firstindex(str)

    scheme_start = idx
    scheme_end = nothing
    sep = findfirst("://", str)
    if sep !== nothing
        scheme_end = first(sep) - 1
        idx = last(sep) + 1
        uri.scheme = _cursor_slice(buf, scheme_start, scheme_end)
    else
        uri.scheme = null_cursor()
    end

    authority_start = idx
    authority_end = n
    for i in idx:n
        c = str[i]
        if c == '/' || c == '?'
            authority_end = i - 1
            break
        end
    end

    uri.authority = authority_end >= authority_start ? _cursor_slice(buf, authority_start, authority_end) : null_cursor()

    userinfo = null_cursor()
    user = null_cursor()
    password = null_cursor()
    host_name = null_cursor()
    port = UInt32(0)

    if authority_end >= authority_start
        authority = SubString(str, authority_start, authority_end)
        at_idx = findlast(==('@'), authority)
        hostport_start = authority_start
        if at_idx !== nothing
            at_global = authority_start + at_idx - 1
            if at_global > authority_start
                userinfo = _cursor_slice(buf, authority_start, at_global - 1)
                userinfo_str = SubString(str, authority_start, at_global - 1)
                colon_idx = findfirst(==(':'), userinfo_str)
                if colon_idx !== nothing
                    colon_global = authority_start + colon_idx - 1
                    user = _cursor_slice(buf, authority_start, colon_global - 1)
                    password = _cursor_slice(buf, colon_global + 1, at_global - 1)
                else
                    user = userinfo
                end
            end
            hostport_start = at_global + 1
        end

        if hostport_start <= authority_end
            hostport_str = SubString(str, hostport_start, authority_end)
            if !isempty(hostport_str) && first(hostport_str) == '['
                closing = findfirst(==(']'), hostport_str)
                closing === nothing && return raise_error(ERROR_MALFORMED_INPUT_STRING)
                closing_global = hostport_start + closing - 1
                host_name = _cursor_slice(buf, hostport_start + 1, closing_global - 1)
                if closing_global < authority_end
                    if str[closing_global + 1] != ':'
                        return raise_error(ERROR_MALFORMED_INPUT_STRING)
                    end
                    port_str = SubString(str, closing_global + 2, authority_end)
                    port, ok = _parse_port(port_str)
                    ok || return raise_error(ERROR_MALFORMED_INPUT_STRING)
                end
            else
                colon_idx = findlast(==(':'), hostport_str)
                if colon_idx !== nothing
                    colon_global = hostport_start + colon_idx - 1
                    host_part = SubString(str, hostport_start, colon_global - 1)
                    port_part = SubString(str, colon_global + 1, authority_end)
                    if isempty(host_part) && isempty(port_part)
                        host_name = null_cursor()
                        port = UInt32(0)
                    elseif isempty(port_part)
                        return raise_error(ERROR_MALFORMED_INPUT_STRING)
                    else
                        port, ok = _parse_port(port_part)
                        ok || return raise_error(ERROR_MALFORMED_INPUT_STRING)
                        host_name = isempty(host_part) ? null_cursor() : _cursor_slice(buf, hostport_start, colon_global - 1)
                    end
                else
                    host_name = _cursor_slice(buf, hostport_start, authority_end)
                end
            end
        end
    end

    uri.userinfo = userinfo
    uri.user = user
    uri.password = password
    uri.host_name = host_name
    uri.port = port

    path = null_cursor()
    query_string = null_cursor()
    path_and_query = null_cursor()

    if authority_end < n
        next_idx = authority_end + 1
        if str[next_idx] == '/'
            query_idx = findnext(==('?'), str, next_idx)
            if query_idx === nothing
                path = _cursor_slice(buf, next_idx, n)
            else
                path = _cursor_slice(buf, next_idx, query_idx - 1)
                query_string = _cursor_slice(buf, query_idx + 1, n)
            end
        elseif str[next_idx] == '?'
            query_string = _cursor_slice(buf, next_idx + 1, n)
        end
    end

    uri.path = path
    uri.query_string = query_string
    if path.len != 0
        # Get the position within the buffer using memoryref offset
        start = memref_offset(path.ptr)
        path_and_query = _cursor_slice(buf, start, n)
    elseif query_string.len != 0
        # Get the position within the buffer using memoryref offset
        start = memref_offset(query_string.ptr)
        path_and_query = _cursor_slice(buf, start, n)
    end
    uri.path_and_query = path_and_query

    return OP_SUCCESS
end

function uri_init_parse(uri_ref::Base.RefValue{Uri}, uri_str::ByteCursor)
    uri_ref[] = Uri()
    buf_ref = Ref(uri_ref[].uri_str)
    if byte_buf_init_copy_from_cursor(buf_ref, uri_str) != OP_SUCCESS
        return OP_ERR
    end
    uri_ref[].uri_str = buf_ref[]
    return _parse_uri_from_buffer!(uri_ref[])
end

function uri_init_parse(uri_ref::Base.RefValue{Uri}, uri_str::Base.RefValue{ByteCursor})
    return uri_init_parse(uri_ref, uri_str[])
end

function uri_clean_up(uri_ref::Base.RefValue{Uri})
    buf_ref = Ref(uri_ref[].uri_str)
    byte_buf_clean_up(buf_ref)
    uri = uri_ref[]
    uri.uri_str = buf_ref[]
    uri.scheme = null_cursor()
    uri.authority = null_cursor()
    uri.userinfo = null_cursor()
    uri.user = null_cursor()
    uri.password = null_cursor()
    uri.host_name = null_cursor()
    uri.port = UInt32(0)
    uri.path = null_cursor()
    uri.query_string = null_cursor()
    uri.path_and_query = null_cursor()
    return nothing
end

function _query_params_from_cursor(query::ByteCursor, out_params::ArrayList{UriParam})
    if query.len == 0
        return OP_SUCCESS
    end

    # Use Memory-based indexing
    mem = parent(query.ptr)
    base = memref_offset(query.ptr)  # 1-based starting position in memory
    total = Int(query.len)
    seg_start = 1  # 1-based position within query
    i = 1

    while i <= total + 1
        # Check for end of segment (& or end of string)
        is_end = i > total
        is_amp = !is_end && @inbounds mem[base + i - 1] == UInt8('&')

        if is_end || is_amp
            seg_len = i - seg_start
            if seg_len > 0
                # Find '=' within this segment
                eq_pos = 0
                for j in seg_start:(i - 1)
                    if @inbounds mem[base + j - 1] == UInt8('=')
                        eq_pos = j
                        break
                    end
                end

                if eq_pos == 0
                    # No '=' found - whole segment is the key
                    key = ByteCursor(Csize_t(seg_len), memoryref(query.ptr, seg_start))
                    value = null_cursor()
                else
                    # Split at '='
                    key_len = eq_pos - seg_start
                    key = key_len > 0 ? ByteCursor(Csize_t(key_len), memoryref(query.ptr, seg_start)) : null_cursor()
                    value_len = i - eq_pos - 1
                    value = value_len > 0 ? ByteCursor(Csize_t(value_len), memoryref(query.ptr, eq_pos + 1)) : null_cursor()
                end
                push_back!(out_params, UriParam(key, value))
            end
            seg_start = i + 1
        end
        i += 1
    end
    return OP_SUCCESS
end

function uri_query_string_params(uri_ref::Base.RefValue{Uri}, out_params::ArrayList{UriParam})
    clear!(out_params)
    return _query_params_from_cursor(uri_ref[].query_string, out_params)
end

function uri_query_string_params(uri_ref::Base.RefValue{Uri}, out_params_ref::Base.RefValue{ArrayList{UriParam}})
    return uri_query_string_params(uri_ref, out_params_ref[])
end

function _append_query_params!(buffer::Base.RefValue{ByteBuffer}, params::ArrayList{UriParam})
    for i in 1:params.length
        param = params.data[i]
        byte_buf_append(buffer, Ref(param.key))
        if param.value.len != 0
            byte_buf_append(buffer, Ref(byte_cursor_from_c_str("=")))
            byte_buf_append(buffer, Ref(param.value))
        end
        if i < params.length
            byte_buf_append(buffer, Ref(byte_cursor_from_c_str("&")))
        end
    end
    return OP_SUCCESS
end

function uri_init_from_builder_options(uri_ref::Base.RefValue{Uri}, options::UriBuilderOptions)
    if options.query_string.len != 0 && options.query_params !== nothing
        return raise_error(ERROR_INVALID_ARGUMENT)
    end

    size = options.scheme.len + options.host_name.len + options.path.len
    if options.scheme.len != 0
        size += 3
    end
    if options.port != 0
        size += URI_PORT_BUFFER_SIZE
    end
    if options.query_params !== nothing
        size += 1
        for i in 1:options.query_params.length
            param = options.query_params.data[i]
            size += param.key.len + param.value.len + 2
        end
    elseif options.query_string.len != 0
        size += options.query_string.len + 1
    end

    uri_ref[] = Uri()
    buf_ref = Ref(uri_ref[].uri_str)
    if byte_buf_init(buf_ref, size) != OP_SUCCESS
        return OP_ERR
    end
    uri_ref[].uri_str = buf_ref[]

    buf_ptr = Ref(uri_ref[].uri_str)
    if options.scheme.len != 0
        byte_buf_append(buf_ptr, Ref(options.scheme))
        byte_buf_append(buf_ptr, Ref(byte_cursor_from_c_str("://")))
    end
    byte_buf_append(buf_ptr, Ref(options.host_name))
    if options.port != 0
        byte_buf_append(buf_ptr, Ref(byte_cursor_from_c_str(":")))
        port_str = string(options.port)
        port_cur = byte_cursor_from_c_str(port_str)
        byte_buf_append(buf_ptr, Ref(port_cur))
    end
    if options.path.len != 0
        byte_buf_append(buf_ptr, Ref(options.path))
    end
    if options.query_params !== nothing && options.query_params.length > 0
        byte_buf_append(buf_ptr, Ref(byte_cursor_from_c_str("?")))
        _append_query_params!(buf_ptr, options.query_params)
    elseif options.query_string.len != 0
        byte_buf_append(buf_ptr, Ref(byte_cursor_from_c_str("?")))
        byte_buf_append(buf_ptr, Ref(options.query_string))
    end

    # Copy the updated buffer back to the Uri struct
    uri_ref[].uri_str = buf_ptr[]

    return _parse_uri_from_buffer!(uri_ref[])
end

function uri_init_from_builder_options(uri_ref::Base.RefValue{Uri}, options_ref::Base.RefValue{UriBuilderOptions})
    return uri_init_from_builder_options(uri_ref, options_ref[])
end

# Encoding/decoding helpers - Memory-based implementations
@inline function _to_uppercase_hex(value::UInt8)
    return value < 10 ? UInt8('0') + value : UInt8('A') + (value - 10)
end

@inline function _is_unreserved_path_char(value::UInt8)
    return (value >= UInt8('A') && value <= UInt8('Z')) ||
        (value >= UInt8('a') && value <= UInt8('z')) ||
        (value >= UInt8('0') && value <= UInt8('9')) ||
        value == UInt8('-') || value == UInt8('_') ||
        value == UInt8('.') || value == UInt8('~') || value == UInt8('/')
end

@inline function _is_unreserved_param_char(value::UInt8)
    return (value >= UInt8('A') && value <= UInt8('Z')) ||
        (value >= UInt8('a') && value <= UInt8('z')) ||
        (value >= UInt8('0') && value <= UInt8('9')) ||
        value == UInt8('-') || value == UInt8('_') ||
        value == UInt8('.') || value == UInt8('~')
end

function byte_buf_append_encoding_uri_path(buffer::Base.RefValue{ByteBuffer}, cursor::Base.RefValue{ByteCursor})
    precondition(byte_cursor_is_valid(cursor))
    cur = cursor[]

    # Each byte could expand to 3 bytes (percent encoding)
    capacity_needed = Ref{Csize_t}(0)
    if UNLIKELY(mul_size_checked(Csize_t(3), cur.len, capacity_needed) != OP_SUCCESS)
        return OP_ERR
    end

    if byte_buf_reserve_relative(buffer, capacity_needed[]) != OP_SUCCESS
        return OP_ERR
    end

    buf = buffer[]
    write_idx = Int(buf.len) + 1
    len = Int(cur.len)

    @inbounds for i in 1:len
        value = memoryref(cur.ptr, i)[]
        if _is_unreserved_path_char(value)
            buf.mem[write_idx] = value
            write_idx += 1
        else
            buf.mem[write_idx] = UInt8('%')
            buf.mem[write_idx + 1] = _to_uppercase_hex(value >> 4)
            buf.mem[write_idx + 2] = _to_uppercase_hex(value & 0x0f)
            write_idx += 3
        end
    end

    buffer[].len = Csize_t(write_idx - 1)
    return OP_SUCCESS
end

function byte_buf_append_encoding_uri_param(buffer::Base.RefValue{ByteBuffer}, cursor::Base.RefValue{ByteCursor})
    precondition(byte_cursor_is_valid(cursor))
    cur = cursor[]

    # Each byte could expand to 3 bytes (percent encoding)
    capacity_needed = Ref{Csize_t}(0)
    if UNLIKELY(mul_size_checked(Csize_t(3), cur.len, capacity_needed) != OP_SUCCESS)
        return OP_ERR
    end

    if byte_buf_reserve_relative(buffer, capacity_needed[]) != OP_SUCCESS
        return OP_ERR
    end

    buf = buffer[]
    write_idx = Int(buf.len) + 1
    len = Int(cur.len)

    @inbounds for i in 1:len
        value = memoryref(cur.ptr, i)[]
        if _is_unreserved_param_char(value)
            buf.mem[write_idx] = value
            write_idx += 1
        else
            buf.mem[write_idx] = UInt8('%')
            buf.mem[write_idx + 1] = _to_uppercase_hex(value >> 4)
            buf.mem[write_idx + 2] = _to_uppercase_hex(value & 0x0f)
            write_idx += 3
        end
    end

    buffer[].len = Csize_t(write_idx - 1)
    return OP_SUCCESS
end

function byte_buf_append_decoding_uri(buffer::Base.RefValue{ByteBuffer}, cursor::Base.RefValue{ByteCursor})
    precondition(byte_cursor_is_valid(cursor))
    cur = cursor[]

    if byte_buf_reserve_relative(buffer, cur.len) != OP_SUCCESS
        return OP_ERR
    end

    advancing = Ref(cur)
    byte = Ref{UInt8}(0)
    buf = buffer[]
    write_idx = Int(buf.len) + 1

    while byte_cursor_read_u8(advancing, byte)
        if byte[] == UInt8('%')
            if byte_cursor_read_hex_u8(advancing, byte) == false
                return raise_error(ERROR_MALFORMED_INPUT_STRING)
            end
        end
        @inbounds buf.mem[write_idx] = byte[]
        write_idx += 1
    end

    buffer[].len = Csize_t(write_idx - 1)
    return OP_SUCCESS
end
