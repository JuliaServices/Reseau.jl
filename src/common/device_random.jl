const _DEVICE_RANDOM_MAX_READ = Csize_t(1024) * Csize_t(1024) * Csize_t(1024)

const _BCRYPT_USE_SYSTEM_PREFERRED_RNG = UInt32(0x00000002)
const _DEV_URANDOM = let bytes = codeunits("/dev/urandom\0")
    data = Memory{UInt8}(undef, length(bytes))
    copyto!(data, bytes)
    data
end
const _device_random_fd = Ref{Cint}(-1)
const _device_random_lock = ReentrantLock()
const _device_random_initialized = Ref{Bool}(false)

@static if !_PLATFORM_WINDOWS
    const _O_RDONLY = Cint(Base.Filesystem.JL_O_RDONLY)
    const _O_CLOEXEC = @static if isdefined(Base.Filesystem, :JL_O_CLOEXEC)
        Cint(Base.Filesystem.JL_O_CLOEXEC)
    else
        Cint(0)
    end
    const _F_SETFD = Cint(2)
    const _FD_CLOEXEC = Cint(1)

    function _device_random_init()
        flags = _O_RDONLY
        if _O_CLOEXEC != 0
            flags |= _O_CLOEXEC
        end
        fd = ccall(:open, Cint, (Ptr{UInt8}, Cint), _DEV_URANDOM, flags)
        if fd == -1
            fd = ccall(:open, Cint, (Ptr{UInt8}, Cint), _DEV_URANDOM, _O_RDONLY)
            if fd == -1
                ccall(:abort, Cvoid, ())
            end
        end
        _device_random_fd[] = fd
        if _fcntl(fd, _F_SETFD, _FD_CLOEXEC) == -1
            ccall(:abort, Cvoid, ())
        end
        return nothing
    end
end

function _device_random_ensure_init()
    lock(_device_random_lock)
    try
        _device_random_initialized[] && return nothing
        _device_random_init()
        _device_random_initialized[] = true
    finally
        unlock(_device_random_lock)
    end
    return nothing
end

function device_random_buffer_append(output::Base.RefValue{<:ByteBuffer}, n::Csize_t)
    buf = output[]
    mem = buf.mem
    space_available = Csize_t(length(mem)) - buf.len
    if space_available < n
        return raise_error(ERROR_SHORT_BUFFER)
    end
    original_len = buf.len
    len = Int(buf.len)
    remaining = Int(n)

    @static if _PLATFORM_WINDOWS
        while remaining > 0
            capped_n = Int(min_size(Csize_t(remaining), Csize_t(typemax(UInt32))))
            status = GC.@preserve mem begin
                ccall(
                    (:BCryptGenRandom, "bcrypt"),
                    Int32,
                    (Ptr{Cvoid}, Ptr{UInt8}, UInt32, UInt32),
                    C_NULL,
                    pointer(mem) + len,
                    UInt32(capped_n),
                    _BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            end
            if status < 0
                output[] = ByteBuffer(mem, original_len)
                return raise_error(ERROR_RANDOM_GEN_FAILED)
            end
            len += capped_n
            remaining -= capped_n
        end
    else
        _device_random_ensure_init()
        fd = _device_random_fd[]
        while remaining > 0
            capped_n = Int(min_size(Csize_t(remaining), _DEVICE_RANDOM_MAX_READ))
            amount_read = GC.@preserve mem begin
                ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, pointer(mem) + len, Csize_t(capped_n))
            end
            if amount_read <= 0
                output[] = ByteBuffer(mem, original_len)
                return raise_error(ERROR_RANDOM_GEN_FAILED)
            end
            len += Int(amount_read)
            remaining -= Int(amount_read)
        end
    end

    output[] = ByteBuffer(mem, Csize_t(len))
    return OP_SUCCESS
end

function device_random_buffer_append(output::Base.RefValue{<:ByteBuffer}, n::Integer)
    return device_random_buffer_append(output, Csize_t(n))
end

function device_random_buffer(output::Base.RefValue{<:ByteBuffer})
    buf = output[]
    return device_random_buffer_append(output, Csize_t(length(buf.mem)) - buf.len)
end

function device_random_u64(output::Ref{UInt64})
    mem = Memory{UInt8}(undef, sizeof(UInt64))
    buf = Ref(ByteBuffer(mem, Csize_t(0)))
    rv = device_random_buffer(buf)
    if rv == OP_SUCCESS
        output[] = GC.@preserve mem begin
            unsafe_load(Ptr{UInt64}(pointer(mem)))
        end
    end
    return rv
end

function device_random_u32(output::Ref{UInt32})
    mem = Memory{UInt8}(undef, sizeof(UInt32))
    buf = Ref(ByteBuffer(mem, Csize_t(0)))
    rv = device_random_buffer(buf)
    if rv == OP_SUCCESS
        output[] = GC.@preserve mem begin
            unsafe_load(Ptr{UInt32}(pointer(mem)))
        end
    end
    return rv
end

function device_random_u16(output::Ref{UInt16})
    mem = Memory{UInt8}(undef, sizeof(UInt16))
    buf = Ref(ByteBuffer(mem, Csize_t(0)))
    rv = device_random_buffer(buf)
    if rv == OP_SUCCESS
        output[] = GC.@preserve mem begin
            unsafe_load(Ptr{UInt16}(pointer(mem)))
        end
    end
    return rv
end

function device_random_u8(output::Ref{UInt8})
    mem = Memory{UInt8}(undef, sizeof(UInt8))
    buf = Ref(ByteBuffer(mem, Csize_t(0)))
    rv = device_random_buffer(buf)
    if rv == OP_SUCCESS
        output[] = mem[1]
    end
    return rv
end
