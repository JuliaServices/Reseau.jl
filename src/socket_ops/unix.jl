# Filesystem Unix-domain addresses. Linux has a 16-bit family; BSD has a
# length byte followed by an 8-bit family. Both layouts put the path at byte 2.
@static if Sys.islinux()
    const _UNIX_PATH_CAPACITY = 108
    struct SockAddrUn
        sun_family::UInt16
        sun_path::NTuple{_UNIX_PATH_CAPACITY, UInt8}
    end
else
    const _UNIX_PATH_CAPACITY = 104
    struct SockAddrUn
        sun_len::UInt8
        sun_family::UInt8
        sun_path::NTuple{_UNIX_PATH_CAPACITY, UInt8}
    end
end

function sockaddr_un(path::String)::SockAddrUn
    n = sizeof(path)
    n > 0 || throw(ArgumentError("Unix socket path must not be empty"))
    n < _UNIX_PATH_CAPACITY || throw(ArgumentError("Unix socket path exceeds $(_UNIX_PATH_CAPACITY - 1) bytes"))
    bytes = codeunits(path)
    any(iszero, bytes) && throw(ArgumentError("Unix socket path must not contain NUL"))
    data = ntuple(i -> i <= n ? bytes[i] : UInt8(0), Val(_UNIX_PATH_CAPACITY))
    @static if Sys.islinux()
        return SockAddrUn(UInt16(AF_UNIX), data)
    else
        return SockAddrUn(UInt8(3 + n), UInt8(AF_UNIX), data)
    end
end

function connect_socket(fd::SocketFD, addr::SockAddrUn, pathbytes::Int)::Int32
    addr_ref = Ref(addr)
    return GC.@preserve addr_ref connect_socket(
        fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(3 + pathbytes),
    )
end

function check_peer_name_un(fd::SocketFD)
    addr = Ref{SockAddrUn}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrUn)))
    ret = @ccall getpeername(fd::SocketFD, addr::Ref{SockAddrUn}, addrlen::Ref{SockLen})::Cint
    ret == 0 || throw(SystemError("getpeername", Int(last_error())))
    return nothing
end
