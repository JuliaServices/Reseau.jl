const _IS_LITTLE_ENDIAN = Base.ENDIAN_BOM == 0x04030201

function is_big_endian()
    return _IS_LITTLE_ENDIAN ? 0 : 1
end

function hton64(x::UInt64)
    return _IS_LITTLE_ENDIAN ? bswap(x) : x
end

function ntoh64(x::UInt64)
    return hton64(x)
end

function hton32(x::UInt32)
    return _IS_LITTLE_ENDIAN ? bswap(x) : x
end

function ntoh32(x::UInt32)
    return hton32(x)
end

function hton16(x::UInt16)
    return _IS_LITTLE_ENDIAN ? bswap(x) : x
end

function ntoh16(x::UInt16)
    return hton16(x)
end

function htonf32(x::Float32)
    if _IS_LITTLE_ENDIAN
        return reinterpret(Float32, bswap(reinterpret(UInt32, x)))
    end
    return x
end

function ntohf32(x::Float32)
    return htonf32(x)
end

function htonf64(x::Float64)
    if _IS_LITTLE_ENDIAN
        return reinterpret(Float64, bswap(reinterpret(UInt64, x)))
    end
    return x
end

function ntohf64(x::Float64)
    return htonf64(x)
end
