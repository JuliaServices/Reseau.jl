export DNSError, getalladdrinfo, getaddrinfo, getnameinfo, getipaddr, getipaddrs, islinklocaladdr

using ..Reseau: _PLATFORM_WINDOWS, _PLATFORM_LINUX, _PLATFORM_APPLE
using ..Reseau: getalladdrinfo as _reseau_getalladdrinfo

"""
    DNSError

Exception thrown when an error occurs in DNS lookup.
"""
struct DNSError <: Exception
    host::String
    code::Int32
end

function Base.show(io::IO, err::DNSError)
    print(io, "DNSError: ", err.host, ", error_code=", err.code)
end

function getalladdrinfo(host::AbstractString)::Vector{IPAddr}
    raw = _reseau_getalladdrinfo(host)
    addrs = IPAddr[]
    for (addr, family) in raw
        # family: AF_INET / AF_INET6.
        if family == _AF_INET
            push!(addrs, parse(IPv4, addr))
        elseif family == _AF_INET6
            push!(addrs, parse(IPv6, addr))
        end
    end
    isempty(addrs) && throw(DNSError(String(host), Int32(-1)))
    return addrs
end

function getaddrinfo(host::AbstractString, T::Type{<:IPAddr})::IPAddr
    addrs = getalladdrinfo(host)
    for addr in addrs
        if addr isa T
            return addr
        end
    end
    throw(DNSError(String(host), Int32(-1)))
end

function getaddrinfo(host::AbstractString)::IPAddr
    addrs = getalladdrinfo(host)
    return addrs[begin]
end

# --- getnameinfo (reverse lookup) ---

@static if _PLATFORM_WINDOWS
    const _AF_INET = Cint(2)
    const _AF_INET6 = Cint(23)
elseif _PLATFORM_APPLE
    const _AF_INET = Cint(2)
    const _AF_INET6 = Cint(30)
else
    const _AF_INET = Cint(2)
    const _AF_INET6 = Cint(10)
end

@static if _PLATFORM_WINDOWS
    # Winsock getnameinfo expects sockaddr in winsock2.h layouts; we build those in-memory.
    const _NI_MAXHOST = 1025
    const _NI_NAMEREQD = Cint(0x04)
    const _NI_NUMERICHOST = Cint(0x02)
else
    const _NI_MAXHOST = 1025
    const _NI_NAMEREQD = Cint(0x04)
    const _NI_NUMERICHOST = Cint(0x02)
end

function _sockaddr_ipv4_bytes(ip::IPv4)
    h = ip.host
    return (
        UInt8((h >> 24) & 0xFF),
        UInt8((h >> 16) & 0xFF),
        UInt8((h >> 8) & 0xFF),
        UInt8(h & 0xFF),
    )
end

function _sockaddr_ipv6_bytes(ip::IPv6)
    h = ip.host
    bytes = ntuple(16) do i
        shift = (16 - i) * 8
        UInt8((h >> shift) & 0xFF)
    end
    return bytes
end

function _hostbuf_to_string(hostbuf::Vector{UInt8})::String
    n = findfirst(==(0x00), hostbuf)
    n === nothing && return String(copy(hostbuf))
    n == 1 && return ""
    return String(copy(hostbuf[1:(n - 1)]))
end

function _getnameinfo_from_sockaddr!(sa::Vector{UInt8}, hostbuf::Vector{UInt8}, flags::Cint)::Cint
    fill!(hostbuf, 0x00)
    return GC.@preserve sa hostbuf begin
        @static if _PLATFORM_WINDOWS
            @ccall "Ws2_32".getnameinfo(
                pointer(sa)::Ptr{Cvoid},
                Cuint(length(sa))::Cuint,
                pointer(hostbuf)::Ptr{UInt8},
                Cuint(length(hostbuf))::Cuint,
                C_NULL::Ptr{UInt8},
                Cuint(0)::Cuint,
                flags::Cint,
            )::Cint
        else
            @ccall getnameinfo(
                pointer(sa)::Ptr{Cvoid},
                Cuint(length(sa))::Cuint,
                pointer(hostbuf)::Ptr{UInt8},
                Cuint(length(hostbuf))::Cuint,
                C_NULL::Ptr{UInt8},
                Cuint(0)::Cuint,
                flags::Cint,
            )::Cint
        end
    end
end

function getnameinfo(address::Union{IPv4, IPv6})::String
    hostbuf = Vector{UInt8}(undef, _NI_MAXHOST)
    if address isa IPv4
        # sockaddr_in
        sa = Vector{UInt8}(undef, 16)
        fill!(sa, 0x00)
        @static if _PLATFORM_APPLE
            sa[1] = UInt8(length(sa))      # sin_len
            sa[2] = UInt8(_AF_INET)        # sin_family
        else
            sa[1:2] .= reinterpret(UInt8, [UInt16(_AF_INET)])
        end

        b1, b2, b3, b4 = _sockaddr_ipv4_bytes(address)
        sa[5] = b1
        sa[6] = b2
        sa[7] = b3
        sa[8] = b4
    else
        # sockaddr_in6
        sa = Vector{UInt8}(undef, 28)
        fill!(sa, 0x00)
        @static if _PLATFORM_APPLE
            sa[1] = UInt8(length(sa))      # sin6_len
            sa[2] = UInt8(_AF_INET6)       # sin6_family
        else
            sa[1:2] .= reinterpret(UInt8, [UInt16(_AF_INET6)])
        end

        bytes = _sockaddr_ipv6_bytes(address)
        @inbounds for i in 1:16
            sa[9 + (i - 1)] = bytes[i]
        end
    end

    # Match stdlib `Sockets.getnameinfo` behavior: try name resolution first, and
    # fall back to a numeric representation if no PTR record exists.
    rc = _getnameinfo_from_sockaddr!(sa, hostbuf, _NI_NAMEREQD)
    if rc != 0
        rc2 = _getnameinfo_from_sockaddr!(sa, hostbuf, _NI_NUMERICHOST)
        rc2 != 0 && throw(DNSError(repr(address), Int32(rc)))
    end

    return _hostbuf_to_string(hostbuf)
end

# --- Interface enumeration (libuv-free) ---

@static if _PLATFORM_WINDOWS
    # Windows interface enumeration via GetAdaptersAddresses (iphlpapi).
    #
    # Reference:
    # - https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    # - https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh

    const _AF_UNSPEC = Cuint(0)

    const _GAA_FLAG_SKIP_UNICAST = Cuint(0x0001)
    const _GAA_FLAG_SKIP_ANYCAST = Cuint(0x0002)
    const _GAA_FLAG_SKIP_MULTICAST = Cuint(0x0004)
    const _GAA_FLAG_SKIP_DNS_SERVER = Cuint(0x0008)
    const _GAA_FLAG_INCLUDE_PREFIX = Cuint(0x0010)

    const _ERROR_BUFFER_OVERFLOW = UInt32(111)
    const _ERROR_SUCCESS = UInt32(0)

    # See IP_ADAPTER_UNICAST_ADDRESS in iptypes.h
    struct _SOCKET_ADDRESS
        lpSockaddr::Ptr{Cvoid}
        iSockaddrLength::Cint
    end

    # The real IP_ADAPTER_UNICAST_ADDRESS has more fields; we only need the prefix.
    struct _IP_ADAPTER_UNICAST_ADDRESS
        length::UInt32
        flags::UInt32
        next::Ptr{Cvoid}
        address::_SOCKET_ADDRESS
    end

    # The real IP_ADAPTER_ADDRESSES has many fields; we only need the prefix up through FirstUnicastAddress.
    #
    # Layout notes:
    # - `union { ULONG Alignment; struct { ULONG Length; ULONG IfIndex; }; }` => model as 2 UInt32.
    # - Pointers are Ptr{Cvoid} (64-bit on Windows CI).
    struct _IP_ADAPTER_ADDRESSES
        length::UInt32
        if_index::UInt32
        next::Ptr{Cvoid}
        adapter_name::Ptr{UInt8}
        first_unicast::Ptr{Cvoid}
        first_anycast::Ptr{Cvoid}
        first_multicast::Ptr{Cvoid}
        first_dns_server::Ptr{Cvoid}
        dns_suffix::Ptr{UInt16}
        description::Ptr{UInt16}
        friendly_name::Ptr{UInt16}
        physical_address::NTuple{8, UInt8}
        physical_address_length::UInt32
        flags::UInt32
        mtu::UInt32
        if_type::UInt32
        oper_status::UInt32
        ipv6_if_index::UInt32
        zone_indices::NTuple{16, UInt32}
        first_prefix::Ptr{Cvoid}
    end

    @inline function _win_getadaptersaddresses!(buf::Vector{UInt8}, buflen::Ref{UInt32})::UInt32
        flags = _GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST | _GAA_FLAG_SKIP_DNS_SERVER
        return GC.@preserve buf begin
            @ccall "iphlpapi".GetAdaptersAddresses(
                _AF_UNSPEC::Cuint,
                flags::Cuint,
                C_NULL::Ptr{Cvoid},
                pointer(buf)::Ptr{_IP_ADAPTER_ADDRESSES},
                buflen::Ref{UInt32},
            )::UInt32
        end
    end

    function getipaddrs(::Type{T} = IPAddr; loopback::Bool = false) where {T<:IPAddr}
        addrs = T[]

        # Buffer sizing pattern per Microsoft docs.
        buflen = Ref{UInt32}(UInt32(15_000))
        buf = Vector{UInt8}(undef, Int(buflen[]))
        rc = _win_getadaptersaddresses!(buf, buflen)
        if rc == _ERROR_BUFFER_OVERFLOW
            resize!(buf, Int(buflen[]))
            rc = _win_getadaptersaddresses!(buf, buflen)
        end
        rc == _ERROR_SUCCESS || error("GetAdaptersAddresses failed: $(rc)")

        buf_start = UInt(pointer(buf))
        buf_end = buf_start + UInt(length(buf))

        p = Ptr{_IP_ADAPTER_ADDRESSES}(pointer(buf))
        adapters_seen = 0
        while p != C_NULL
            adapters_seen += 1
            # Defensive: avoid infinite loops / corrupted lists.
            adapters_seen > 1024 && break

            p_addr = UInt(p)
            (p_addr < buf_start || (p_addr + UInt(sizeof(_IP_ADAPTER_ADDRESSES)) > buf_end)) && break

            aa = unsafe_load(p)
            up = Ptr{_IP_ADAPTER_UNICAST_ADDRESS}(aa.first_unicast)
            unicast_seen = 0
            while up != C_NULL
                unicast_seen += 1
                unicast_seen > 65536 && break

                up_addr = UInt(up)
                (up_addr < buf_start || (up_addr + UInt(sizeof(_IP_ADAPTER_UNICAST_ADDRESS)) > buf_end)) && break

                ua = unsafe_load(up)
                sa = ua.address.lpSockaddr
                if sa != C_NULL
                    sa_addr = UInt(sa)
                    # sockaddr first field is sa_family (UInt16) on Windows.
                    if sa_addr >= buf_start && (sa_addr + UInt(2) <= buf_end)
                        family = unsafe_load(Ptr{UInt16}(sa))
                    else
                        family = UInt16(0)
                    end
                    if family == UInt16(_AF_INET) && (sa_addr + UInt(8) <= buf_end)
                        bytes = unsafe_wrap(Vector{UInt8}, Ptr{UInt8}(sa) + 4, 4; own = false)
                        ip = IPv4(bytes[1], bytes[2], bytes[3], bytes[4])
                        if (loopback || !_is_loopback(ip)) && (T == IPAddr || ip isa T)
                            push!(addrs, ip)
                        end
                    elseif family == UInt16(_AF_INET6) && (sa_addr + UInt(24) <= buf_end)
                        bytes = unsafe_wrap(Vector{UInt8}, Ptr{UInt8}(sa) + 8, 16; own = false)
                        host = UInt128(0)
                        @inbounds for i in 1:16
                            host = (host << 8) | UInt128(bytes[i])
                        end
                        ip = IPv6(host)
                        if (loopback || !_is_loopback(ip)) && (T == IPAddr || ip isa T)
                            push!(addrs, ip)
                        end
                    end
                end
                up = Ptr{_IP_ADAPTER_UNICAST_ADDRESS}(ua.next)
            end
            p = Ptr{_IP_ADAPTER_ADDRESSES}(aa.next)
        end

        # Guarantee loopback availability for parity with the stdlib contract.
        if loopback
            if T == IPAddr || T == IPv4
                lo4 = IPv4("127.0.0.1")
                lo4 in addrs || push!(addrs, lo4)
            end
            if T == IPAddr || T == IPv6
                lo6 = IPv6("::1")
                lo6 in addrs || push!(addrs, lo6)
            end
        end

        return addrs
    end
else
    # ifaddrs list
    struct _ifaddrs
        ifa_next::Ptr{Cvoid}
        ifa_name::Ptr{UInt8}
        ifa_flags::UInt32
        ifa_addr::Ptr{Cvoid}
        ifa_netmask::Ptr{Cvoid}
        ifa_dstaddr::Ptr{Cvoid}
        ifa_data::Ptr{Cvoid}
    end

    const _AF_INET_NUM = UInt16(_AF_INET)
    const _AF_INET6_NUM = UInt16(_AF_INET6)

    function getipaddrs(::Type{T} = IPAddr; loopback::Bool = false) where {T<:IPAddr}
        addrs = T[]
        ifap = Ref{Ptr{Cvoid}}(C_NULL)
        rc = @ccall getifaddrs(ifap::Ref{Ptr{Cvoid}})::Cint
        rc != 0 && error("getifaddrs failed")
        try
            p = ifap[]
            while p != C_NULL
                ifa = unsafe_load(Ptr{_ifaddrs}(p))
                addr = ifa.ifa_addr
                if addr != C_NULL
                    # family is at offset 0 on Linux, offset 1 on Apple/BSD (sa_len then sa_family).
                    family = @static _PLATFORM_APPLE ? unsafe_load(Ptr{UInt8}(addr + 1)) : unsafe_load(Ptr{UInt16}(addr))
                    if family == _AF_INET_NUM
                        bytes = unsafe_wrap(Vector{UInt8}, Ptr{UInt8}(addr + 4), 4; own = false)
                        ip = IPv4(bytes[1], bytes[2], bytes[3], bytes[4])
                        if (loopback || !_is_loopback(ip)) && (T == IPAddr || ip isa T)
                            push!(addrs, ip)
                        end
                    elseif family == _AF_INET6_NUM
                        bytes = unsafe_wrap(Vector{UInt8}, Ptr{UInt8}(addr + 8), 16; own = false)
                        host = UInt128(0)
                        @inbounds for i in 1:16
                            host = (host << 8) | UInt128(bytes[i])
                        end
                        ip = IPv6(host)
                        if (loopback || !_is_loopback(ip)) && (T == IPAddr || ip isa T)
                            push!(addrs, ip)
                        end
                    end
                end
                p = ifa.ifa_next
            end
        finally
            @ccall freeifaddrs(ifap[]::Ptr{Cvoid})::Cvoid
        end
        return addrs
    end
end

@inline function _is_loopback(ip::IPv4)::Bool
    return (ip.host & 0xFF000000) == 0x7F000000
end

@inline function _is_loopback(ip::IPv6)::Bool
    return ip.host == UInt128(1)
end

function getipaddr(::Type{T} = IPAddr) where {T<:IPAddr}
    addrs = getipaddrs(T)
    isempty(addrs) && error("No networking interface available")
    # Prefer returning an IPv4 if the requested type is IPAddr.
    if T == IPAddr
        i = something(findfirst(ip -> ip isa IPv4, addrs), 1)
        return addrs[i]
    end
    return addrs[1]
end

function islinklocaladdr(addr::IPAddr)::Bool
    if addr isa IPv4
        # 169.254.0.0/16
        return (addr.host & 0xFFFF0000) == 0xA9FE0000
    else
        # fe80::/10
        top = UInt16((addr.host >> 112) & 0xFFFF)
        return (top & 0xFFC0) == 0xFE80
    end
end
