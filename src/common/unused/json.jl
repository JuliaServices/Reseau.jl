import JSON

const JsonValue = Any
const json_value = JsonValue

@inline function _cursor_to_string(cur::ByteCursor)
    return cursor_to_string(cur)
end

function json_value_new_from_string(cursor::ByteCursor)
    if cursor.len == 0
        raise_error(ERROR_INVALID_ARGUMENT)
        return nothing
    end
    bytes = Vector{UInt8}(undef, Int(cursor.len))
    byte_cursor_read(Ref(ByteCursor(cursor.ptr, cursor.len)), bytes, cursor.len)
    try
        return JSON.parse(bytes)
    catch
        raise_error(ERROR_INVALID_ARGUMENT)
        return nothing
    end
end

function json_value_new_from_string(cursor::Base.RefValue{ByteCursor})
    return json_value_new_from_string(cursor[])
end

json_value_new_string(cursor::ByteCursor) = _cursor_to_string(cursor)
json_value_new_string_from_c_str(str::AbstractString) = str
json_value_new_string_from_c_str(str::Ptr{UInt8}) = unsafe_string(str)
json_value_new_number(number::Real) = Float64(number)
json_value_new_boolean(boolean::Bool) = boolean
json_value_new_null() = nothing
json_value_new_array() = []
json_value_new_object() = JSON.Object()

json_value_is_string(value) = value isa AbstractString
json_value_is_number(value) = value isa Real && !(value isa Bool)
json_value_is_array(value) = value isa AbstractVector
json_value_is_boolean(value) = value isa Bool
json_value_is_null(value) = value === nothing
json_value_is_object(value) = value isa AbstractDict

function json_value_get_string(value, output::Base.RefValue{ByteCursor})
    if !(value isa AbstractString)
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    output[] = byte_cursor_from_c_str(value)
    return OP_SUCCESS
end

function json_value_get_number(value, output::Base.RefValue{Cdouble})
    if !(value isa Real)
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    output[] = Cdouble(value)
    return OP_SUCCESS
end

function json_value_get_boolean(value, output::Base.RefValue{Bool})
    if !(value isa Bool)
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    output[] = value
    return OP_SUCCESS
end

function json_value_get_from_object(object, key::ByteCursor)
    object isa AbstractDict || return nothing
    return get(object, _cursor_to_string(key), nothing)
end

function json_value_get_from_object_c_str(object, key::AbstractString)
    object isa AbstractDict || return nothing
    return get(object, key, nothing)
end

function json_value_has_key(object, key::ByteCursor)
    object isa AbstractDict || return false
    return haskey(object, _cursor_to_string(key))
end

function json_value_has_key_c_str(object, key::AbstractString)
    object isa AbstractDict || return false
    return haskey(object, key)
end

function json_value_add_to_object(object, key::ByteCursor, value)
    object isa AbstractDict || return raise_error(ERROR_INVALID_ARGUMENT)
    object[_cursor_to_string(key)] = value
    return OP_SUCCESS
end

function json_value_add_to_object_c_str(object, key::AbstractString, value)
    object isa AbstractDict || return raise_error(ERROR_INVALID_ARGUMENT)
    object[key] = value
    return OP_SUCCESS
end

function json_value_remove_from_object(object, key::ByteCursor)
    object isa AbstractDict || return raise_error(ERROR_INVALID_ARGUMENT)
    delete!(object, _cursor_to_string(key))
    return OP_SUCCESS
end

function json_value_remove_from_object_c_str(object, key::AbstractString)
    object isa AbstractDict || return raise_error(ERROR_INVALID_ARGUMENT)
    delete!(object, key)
    return OP_SUCCESS
end

function json_value_add_array_element(array, value)
    array isa AbstractVector || return raise_error(ERROR_INVALID_ARGUMENT)
    Base.push!(array, value)
    return OP_SUCCESS
end

function json_get_array_element(array, index::Integer)
    array isa AbstractVector || return nothing
    idx = index + 1
    idx < 1 && return nothing
    idx > length(array) && return nothing
    return array[idx]
end

function json_get_array_size(array)
    array isa AbstractVector || return 0
    return length(array)
end

function json_value_remove_array_element(array, index::Integer)
    array isa AbstractVector || return raise_error(ERROR_INVALID_ARGUMENT)
    idx = index + 1
    idx < 1 && return raise_error(ERROR_INVALID_ARGUMENT)
    idx > length(array) && return raise_error(ERROR_INVALID_ARGUMENT)
    deleteat!(array, idx)
    return OP_SUCCESS
end

function json_value_compare(a, b, is_case_sensitive::Bool)
    if json_value_is_string(a) && json_value_is_string(b)
        return is_case_sensitive ? a == b : _ascii_casefold_equal(a, b)
    end
    if json_value_is_number(a) && json_value_is_number(b)
        return a == b
    end
    if json_value_is_boolean(a) && json_value_is_boolean(b)
        return a == b
    end
    if json_value_is_null(a) && json_value_is_null(b)
        return true
    end
    if json_value_is_array(a) && json_value_is_array(b)
        length(a) == length(b) || return false
        for i in 1:length(a)
            json_value_compare(a[i], b[i], is_case_sensitive) || return false
        end
        return true
    end
    if json_value_is_object(a) && json_value_is_object(b)
        length(a) == length(b) || return false
        for (k, v) in a
            haskey(b, k) || return false
            json_value_compare(v, b[k], is_case_sensitive) || return false
        end
        return true
    end
    return false
end

@inline function _ascii_lower_byte(b::UInt8)
    return (b >= UInt8('A') && b <= UInt8('Z')) ? (b + 0x20) : b
end

function _ascii_casefold_equal(a::AbstractString, b::AbstractString)
    na = ncodeunits(a)
    nb = ncodeunits(b)
    na == nb || return false
    ac = codeunits(a)
    bc = codeunits(b)
    @inbounds for i in 1:na
        if _ascii_lower_byte(ac[i]) != _ascii_lower_byte(bc[i])
            return false
        end
    end
    return true
end

function json_value_duplicate(value)
    if json_value_is_object(value) || json_value_is_array(value)
        return JSON.parse(JSON.json(value))
    end
    return value
end

json_value_destroy(::Any) = nothing

function byte_buf_append_json_string(value, output::Base.RefValue{ByteBuffer})
    json_str = JSON.json(value)
    cur = byte_cursor_from_c_str(json_str)
    return byte_buf_append_dynamic(output, Ref(cur))
end

function byte_buf_append_json_string_formatted(value, output::Base.RefValue{ByteBuffer})
    return byte_buf_append_json_string(value, output)
end
