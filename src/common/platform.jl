const _PLATFORM_WINDOWS = Sys.iswindows()
const _PLATFORM_LINUX = Sys.islinux()
const _PLATFORM_APPLE = Sys.isapple()

const _IS_LITTLE_ENDIAN = Base.ENDIAN_BOM == 0x04030201

function _words_from_bytes(bytes::AbstractVector{UInt8}, ::Type{T}) where {T}
    word_bytes = sizeof(T)
    if length(bytes) % word_bytes != 0
        error("byte length must be multiple of word size")
    end
    words = Vector{T}(undef, length(bytes) ÷ word_bytes)
    if _IS_LITTLE_ENDIAN
        idx = 1
        for i in 1:length(words)
            word = zero(T)
            for b in 0:(word_bytes - 1)
                word |= T(bytes[idx]) << (8 * b)
                idx += 1
            end
            words[i] = word
        end
    else
        idx = 1
        for i in 1:length(words)
            word = zero(T)
            for _ in 1:word_bytes
                word = (word << 8) | T(bytes[idx])
                idx += 1
            end
            words[i] = word
        end
    end
    return tuple(words...)
end

@static if _PLATFORM_WINDOWS
    const _WINDOWS_SRWLOCK_WORDS = 1
    const _WINDOWS_COND_WORDS = 1
    const _WINDOWS_ONCE_WORDS = 1
elseif _PLATFORM_APPLE
    if Sys.WORD_SIZE != 64
        error("platform not supported")
    end
    const _PTHREAD_MUTEX_SIZE = 64
    const _PTHREAD_COND_SIZE = 48
    const _PTHREAD_RWLOCK_SIZE = 200
    const _PTHREAD_ONCE_SIZE = 16

    const _PTHREAD_MUTEX_WORDS = _PTHREAD_MUTEX_SIZE ÷ sizeof(UInt)
    const _PTHREAD_COND_WORDS = _PTHREAD_COND_SIZE ÷ sizeof(UInt)
    const _PTHREAD_RWLOCK_WORDS = _PTHREAD_RWLOCK_SIZE ÷ sizeof(UInt)

    const _PTHREAD_MUTEX_INIT_BYTES = let m = Memory{UInt8}(undef, _PTHREAD_MUTEX_SIZE)
        fill!(m, 0x00)
        m[1] = 0xa7
        m[2] = 0xab
        m[3] = 0xaa
        m[4] = 0x32
        m
    end
    const _PTHREAD_COND_INIT_BYTES = let m = Memory{UInt8}(undef, _PTHREAD_COND_SIZE)
        fill!(m, 0x00)
        m[1] = 0xbb
        m[2] = 0xb1
        m[3] = 0xb0
        m[4] = 0x3c
        m
    end
    const _PTHREAD_RWLOCK_INIT_BYTES = let m = Memory{UInt8}(undef, _PTHREAD_RWLOCK_SIZE)
        fill!(m, 0x00)
        m[1] = 0xb4
        m[2] = 0xb3
        m[3] = 0xa8
        m[4] = 0x2d
        m
    end
    const _PTHREAD_ONCE_INIT_BYTES = let m = Memory{UInt8}(undef, _PTHREAD_ONCE_SIZE)
        fill!(m, 0x00)
        m[1] = 0xba
        m[2] = 0xbc
        m[3] = 0xb1
        m[4] = 0x30
        m
    end

    const _PTHREAD_MUTEX_INIT_WORDS = _words_from_bytes(_PTHREAD_MUTEX_INIT_BYTES, UInt)
    const _PTHREAD_COND_INIT_WORDS = _words_from_bytes(_PTHREAD_COND_INIT_BYTES, UInt)
    const _PTHREAD_RWLOCK_INIT_WORDS = _words_from_bytes(_PTHREAD_RWLOCK_INIT_BYTES, UInt)
    const _PTHREAD_ONCE_WORD_TYPE = UInt
    const _PTHREAD_ONCE_WORDS = _PTHREAD_ONCE_SIZE ÷ sizeof(_PTHREAD_ONCE_WORD_TYPE)
    const _PTHREAD_ONCE_INIT_WORDS = _words_from_bytes(_PTHREAD_ONCE_INIT_BYTES, _PTHREAD_ONCE_WORD_TYPE)
elseif _PLATFORM_LINUX
    if Sys.WORD_SIZE != 64
        error("platform not supported")
    end
    const _PTHREAD_MUTEX_SIZE = 40
    const _PTHREAD_COND_SIZE = 48
    const _PTHREAD_RWLOCK_SIZE = 56
    const _PTHREAD_ONCE_SIZE = 4

    const _PTHREAD_MUTEX_WORDS = _PTHREAD_MUTEX_SIZE ÷ sizeof(UInt)
    const _PTHREAD_COND_WORDS = _PTHREAD_COND_SIZE ÷ sizeof(UInt)
    const _PTHREAD_RWLOCK_WORDS = _PTHREAD_RWLOCK_SIZE ÷ sizeof(UInt)

    const _PTHREAD_MUTEX_INIT_WORDS = ntuple(_ -> UInt(0), _PTHREAD_MUTEX_WORDS)
    const _PTHREAD_COND_INIT_WORDS = ntuple(_ -> UInt(0), _PTHREAD_COND_WORDS)
    const _PTHREAD_RWLOCK_INIT_WORDS = ntuple(_ -> UInt(0), _PTHREAD_RWLOCK_WORDS)
    const _PTHREAD_ONCE_WORD_TYPE = UInt32
    const _PTHREAD_ONCE_WORDS = _PTHREAD_ONCE_SIZE ÷ sizeof(_PTHREAD_ONCE_WORD_TYPE)
    const _PTHREAD_ONCE_INIT_WORDS = ntuple(_ -> UInt32(0), _PTHREAD_ONCE_WORDS)
else
    error("platform not supported")
end

@static if _PLATFORM_APPLE
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(6)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(-1)
elseif _PLATFORM_LINUX
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(1)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(7)
end

@inline function _fcntl(fd::Cint, cmd::Cint, arg::Cint = Cint(0))::Cint
    @static if _PLATFORM_WINDOWS
        return Cint(-1)
    else
        return @ccall fcntl(fd::Cint, cmd::Cint; arg::Cint)::Cint
    end
end
