struct HashEq{H,Eq}
    hash::H
    eq::Eq
end

struct NoopDestroy end
(::NoopDestroy)(_) = nothing

mutable struct HashTable{K,V,HE,OnKeyDestroy,OnValDestroy}
    hash_eq::HE
    on_key_destroy::OnKeyDestroy
    on_val_destroy::OnValDestroy
    keys::Memory{K}
    values::Memory{V}
    hashes::Memory{UInt64}
    states::Memory{UInt8}
    size::Int
    capacity::Int
    max_load::Int
    max_load_factor::Float64
end

const hash_table = HashTable

const _HASH_EMPTY = UInt8(0)
const _HASH_FILLED = UInt8(1)
const _HASH_TOMBSTONE = UInt8(2)

@inline function _next_pow2(n::Int)
    n <= 1 && return 1
    return 1 << (sizeof(Int) * 8 - leading_zeros(n - 1))
end

@inline function _hash_index(hash::UInt64, capacity::Int)
    return Int(hash & UInt64(capacity - 1)) + 1
end

function HashTable{K,V}(
    hash_eq::HashEq{H,Eq};
    capacity::Integer=16,
    max_load_factor::Real=0.75,
    on_key_destroy::OnKeyDestroy=NoopDestroy(),
    on_val_destroy::OnValDestroy=NoopDestroy(),
) where {K,V,H,Eq,OnKeyDestroy,OnValDestroy}
    cap = max(2, _next_pow2(Int(capacity)))
    keys = Memory{K}(undef, cap)
    values = Memory{V}(undef, cap)
    hashes = Memory{UInt64}(undef, cap)
    states = Memory{UInt8}(undef, cap)
    for i in 1:cap
        states[i] = _HASH_EMPTY
    end
    max_load = floor(Int, cap * float(max_load_factor))
    return HashTable{K,V,HashEq{H,Eq},OnKeyDestroy,OnValDestroy}(
        hash_eq,
        on_key_destroy,
        on_val_destroy,
        keys,
        values,
        hashes,
        states,
        0,
        cap,
        max_load,
        float(max_load_factor),
    )
end

function HashTable{K,V}(hash_fn, eq_fn; kwargs...) where {K,V}
    return HashTable{K,V}(HashEq(hash_fn, eq_fn); kwargs...)
end

@inline Base.length(table::HashTable) = table.size

function _find_slot(table::HashTable{K,V}, key) where {K,V}
    hash = UInt64(table.hash_eq.hash(key))
    cap = table.capacity
    idx = _hash_index(hash, cap)
    first_tombstone = 0
    for probe in 0:(cap - 1)
        slot = idx + probe
        slot > cap && (slot -= cap)
        state = table.states[slot]
        if state == _HASH_EMPTY
            slot = first_tombstone == 0 ? slot : first_tombstone
            return false, slot, hash
        elseif state == _HASH_TOMBSTONE
            first_tombstone == 0 && (first_tombstone = slot)
        else
            if table.hashes[slot] == hash && table.hash_eq.eq(table.keys[slot], key)
                return true, slot, hash
            end
        end
    end
    return false, first_tombstone, hash
end

function _insert_raw!(
    keys::Memory{K},
    values::Memory{V},
    hashes::Memory{UInt64},
    states::Memory{UInt8},
    capacity::Int,
    key::K,
    value::V,
    hash::UInt64,
) where {K,V}
    idx = _hash_index(hash, capacity)
    while true
        state = states[idx]
        if state != _HASH_FILLED
            keys[idx] = key
            values[idx] = value
            hashes[idx] = hash
            states[idx] = _HASH_FILLED
            return nothing
        end
        idx += 1
        idx > capacity && (idx = 1)
    end
end

function _rehash!(table::HashTable, new_capacity::Int)
    cap = max(2, _next_pow2(new_capacity))
    new_keys = Memory{eltype(table.keys)}(undef, cap)
    new_values = Memory{eltype(table.values)}(undef, cap)
    new_hashes = Memory{UInt64}(undef, cap)
    new_states = Memory{UInt8}(undef, cap)
    for i in 1:cap
        new_states[i] = _HASH_EMPTY
    end

    for i in 1:table.capacity
        if table.states[i] == _HASH_FILLED
            _insert_raw!(
                new_keys,
                new_values,
                new_hashes,
                new_states,
                cap,
                table.keys[i],
                table.values[i],
                table.hashes[i],
            )
        end
    end

    table.keys = new_keys
    table.values = new_values
    table.hashes = new_hashes
    table.states = new_states
    table.capacity = cap
    table.max_load = floor(Int, cap * table.max_load_factor)
    return nothing
end

function hash_table_put!(table::HashTable{K,V}, key::K, value::V) where {K,V}
    table.size + 1 > table.max_load && _rehash!(table, table.capacity * 2)
    found, slot, hash = _find_slot(table, key)
    if found
        existing_key = table.keys[slot]
        existing_val = table.values[slot]
        table.on_val_destroy(existing_val)
        if key !== existing_key
            table.on_key_destroy(existing_key)
        end
        table.keys[slot] = key
        table.values[slot] = value
        table.hashes[slot] = hash
        return OP_SUCCESS
    end
    slot == 0 && return raise_error(ERROR_NO_SPACE)
    table.keys[slot] = key
    table.values[slot] = value
    table.hashes[slot] = hash
    table.states[slot] = _HASH_FILLED
    table.size += 1
    return OP_SUCCESS
end

function hash_table_get(table::HashTable, key)
    found, slot, _ = _find_slot(table, key)
    found || return nothing
    return table.values[slot]
end

function hash_table_get_entry(table::HashTable, key)
    found, slot, _ = _find_slot(table, key)
    found || return false, nothing
    return true, table.values[slot]
end

function hash_table_get_key(table::HashTable, key)
    found, slot, _ = _find_slot(table, key)
    found || return nothing
    return table.keys[slot]
end

function hash_table_remove!(table::HashTable, key)
    found, slot, _ = _find_slot(table, key)
    found || return nothing
    table.on_key_destroy(table.keys[slot])
    table.on_val_destroy(table.values[slot])
    table.states[slot] = _HASH_TOMBSTONE
    table.size -= 1
    return OP_SUCCESS
end

function hash_table_clear!(table::HashTable)
    for i in 1:table.capacity
        if table.states[i] == _HASH_FILLED
            table.on_key_destroy(table.keys[i])
            table.on_val_destroy(table.values[i])
        end
        table.states[i] = _HASH_EMPTY
    end
    table.size = 0
    return nothing
end

@inline hash_table_get_entry_count(table::HashTable) = table.size

function hash_table_eq(table_a::HashTable, table_b::HashTable; value_eq=isequal)
    length(table_a) == length(table_b) || return false
    for (key, value) in table_a
        other = hash_table_get(table_b, key)
        other === nothing && return false
        value_eq(value, other) || return false
    end
    return true
end

function Base.iterate(table::HashTable, state::Int=1)
    i = state
    while i <= table.capacity
        if table.states[i] == _HASH_FILLED
            return (table.keys[i] => table.values[i], i + 1)
        end
        i += 1
    end
    return nothing
end

function hash_table_foreach(f::Function, table::HashTable)
    for (key, value) in table
        f(key, value)
    end
    return nothing
end

hash_table_foreach(table::HashTable, f::Function) = hash_table_foreach(f, table)

function _fnv1a(ptr::Ptr{UInt8}, len::Integer)
    h = UInt64(0xcbf29ce484222325)
    for i in 0:(Int(len) - 1)
        h ⊻= UInt64(unsafe_load(ptr + i))
        h *= UInt64(0x100000001b3)
    end
    return h
end

function _fnv1a_cursor(cur::ByteCursor)
    h = UInt64(0xcbf29ce484222325)
    @inbounds for i in 1:Int(cur.len)
        h ⊻= UInt64(cursor_getbyte(cur, i))
        h *= UInt64(0x100000001b3)
    end
    return h
end

function hash_c_string(ptr::Ptr{UInt8})
    ptr == C_NULL && return UInt64(0)
    len = ccall(:strlen, Csize_t, (Ptr{UInt8},), ptr)
    return _fnv1a(ptr, len)
end

function hash_string(str::Union{ByteString,Nothing})
    str === nothing && return UInt64(0)
    return _fnv1a(string_bytes(str), string_len(str))
end

function hash_byte_cursor(cur::ByteCursor)
    # Empty cursor returns the FNV-1a initial value
    cur.len == 0 && return UInt64(0xcbf29ce484222325)
    return _fnv1a_cursor(cur)
end

function hash_ptr(ptr::Ptr{Cvoid})
    return UInt64(reinterpret(UInt, ptr))
end

function hash_callback_string_eq(a::Union{ByteString,Nothing}, b::Union{ByteString,Nothing})
    return string_eq(a, b)
end

function hash_callback_string_destroy(str::Union{ByteString,Nothing})
    return string_destroy(str)
end

function ptr_eq(a::Ptr{Cvoid}, b::Ptr{Cvoid})
    return a == b
end
