const _IPV4_STR_LEN = 16
const _percent_uri_enc_bytes = let m = Memory{UInt8}(undef, 2)
    m[1] = UInt8('2')
    m[2] = UInt8('5')
    m
end

@inline function _is_ipv6_char(value::UInt8)
    return isxdigit(value) || value == UInt8(':')
end

# Wrapper for isalnum that explicitly handles UInt8
@inline function _is_alnum(value::UInt8)
    return isalnum(value)
end

function host_utils_is_ipv4(host::ByteCursor)
    if host.len > (_IPV4_STR_LEN - 1)
        return false
    end
    if host.len == 0
        return false
    end
    len = Int(host.len)
    parts = 0
    i = 0
    while i < len
        if parts == 4
            return false
        end
        b = cursor_getbyte(host, i + 1)
        if !isdigit(b)
            return false
        end
        val = 0
        digits = 0
        while i < len
            b = cursor_getbyte(host, i + 1)
            if !isdigit(b)
                break
            end
            val = val * 10 + (b - UInt8('0'))
            digits += 1
            if digits > 3
                return false
            end
            i += 1
        end
        if val > 255
            return false
        end
        parts += 1
        if i == len
            break
        end
        if cursor_getbyte(host, i + 1) != UInt8('.')
            return false
        end
        i += 1
        if i == len
            return false
        end
    end
    return parts == 4
end

function host_utils_is_ipv4(host::Base.RefValue{ByteCursor})
    return host_utils_is_ipv4(host[])
end

function host_utils_is_ipv4(host::Ptr{ByteCursor})
    return host_utils_is_ipv4(unsafe_load(host))
end

function host_utils_is_ipv6(host::ByteCursor, is_uri_encoded::Bool)
    if host.len == 0
        return false
    end
    input_ref = Ref(host)
    substr_ref = Ref{ByteCursor}(null_cursor())
    is_split = byte_cursor_next_split(input_ref, UInt8('%'), substr_ref)
    debug_assert(is_split)
    substr = substr_ref[]
    if !is_split || substr.len < 2 || substr.len > 39 || !byte_cursor_satisfies_pred(substr_ref, _is_ipv6_char)
        return false
    end
    if (cursor_getbyte(substr, 1) == UInt8(':') &&
        (substr.len < 2 || cursor_getbyte(substr, 2) != UInt8(':'))) ||
       (cursor_getbyte(substr, Int(substr.len)) == UInt8(':') &&
        (substr.len < 2 || cursor_getbyte(substr, Int(substr.len) - 1) != UInt8(':')))
        return false
    end

    group_count = UInt8(1)
    digit_count = UInt8(0)
    has_double_colon = false
    for i in 0:(Int(substr.len) - 1)
        if cursor_getbyte(substr, i + 1) == UInt8(':')
            group_count += 1
            digit_count = 0
            if i > 0 && cursor_getbyte(substr, i) == UInt8(':')
                if has_double_colon
                    return false
                end
                has_double_colon = true
                group_count -= 1
            end
        else
            digit_count += 1
        end
        if digit_count > 4 || group_count > 8
            return false
        end
    end

    if byte_cursor_next_split(input_ref, UInt8('%'), substr_ref)
        substr = substr_ref[]
        if is_uri_encoded
            if substr.len < 3
                return false
            end
            # Create ByteCursor from the constant array
            prefix = ByteCursor(_percent_uri_enc_bytes, length(_percent_uri_enc_bytes))
            if !byte_cursor_starts_with(substr_ref, Ref(prefix))
                return false
            end
        else
            if substr.len == 0
                return false
            end
        end
        if !byte_cursor_satisfies_pred(substr_ref, _is_alnum)
            return false
        end
    end

    if has_double_colon
        return group_count <= 8
    end
    return group_count == 8
end

function host_utils_is_ipv6(host::Base.RefValue{ByteCursor}, is_uri_encoded::Bool)
    return host_utils_is_ipv6(host[], is_uri_encoded)
end

function host_utils_is_ipv6(host::Ptr{ByteCursor}, is_uri_encoded::Bool)
    return host_utils_is_ipv6(unsafe_load(host), is_uri_encoded)
end
