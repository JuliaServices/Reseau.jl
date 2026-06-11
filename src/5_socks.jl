"""
    SOCKS

Internal SOCKS5 (RFC 1928) client helpers layered on `TCP.Conn`, including
username/password authentication (RFC 1929).
"""
module SOCKS

using ..Reseau.TCP
using ..Reseau.HostResolvers

const _VERSION5 = UInt8(0x05)
const _AUTH_NO_AUTH = UInt8(0x00)
const _AUTH_USERNAME_PASSWORD = UInt8(0x02)
const _AUTH_NO_ACCEPTABLE = UInt8(0xff)
const _AUTH_USERNAME_PASSWORD_VERSION = UInt8(0x01)
const _AUTH_STATUS_SUCCEEDED = UInt8(0x00)
const _CMD_CONNECT = UInt8(0x01)
const _ADDR_IPV4 = UInt8(0x01)
const _ADDR_FQDN = UInt8(0x03)
const _ADDR_IPV6 = UInt8(0x04)
const _STATUS_SUCCEEDED = UInt8(0x00)

"""
    BoundAddr

SOCKS proxy bound address returned by a successful command reply.
"""
struct BoundAddr
    host::String
    port::UInt16
end

"""
    TargetAddressError

Raised when a SOCKS command target cannot be encoded.
"""
struct TargetAddressError <: Exception
    message::String
    address::String
end

"""
    ProtocolError

Raised when the SOCKS proxy sends malformed protocol bytes.
"""
struct ProtocolError <: Exception
    message::String
end

"""
    AuthenticationError

Raised when SOCKS authentication negotiation fails.
"""
struct AuthenticationError <: Exception
    message::String
end

"""
    ReplyError

Raised when a SOCKS command reply has a non-success status.
"""
struct ReplyError <: Exception
    code::UInt8
    message::String
end

function Base.show(io::IO, addr::BoundAddr)
    print(io, string(addr))
    return nothing
end

function Base.string(addr::BoundAddr)
    return HostResolvers.join_host_port(addr.host, Int(addr.port))
end

function Base.showerror(io::IO, err::TargetAddressError)
    print(io, err.message, ": ", err.address)
    return nothing
end

function Base.showerror(io::IO, err::ProtocolError)
    print(io, err.message)
    return nothing
end

function Base.showerror(io::IO, err::AuthenticationError)
    print(io, err.message)
    return nothing
end

function Base.showerror(io::IO, err::ReplyError)
    print(io, "SOCKS command failed: ", err.message)
    return nothing
end

@inline function _reply_message(code::UInt8)::String
    code == 0x01 && return "general SOCKS server failure"
    code == 0x02 && return "connection not allowed by ruleset"
    code == 0x03 && return "network unreachable"
    code == 0x04 && return "host unreachable"
    code == 0x05 && return "connection refused"
    code == 0x06 && return "TTL expired"
    code == 0x07 && return "command not supported"
    code == 0x08 && return "address type not supported"
    return "unknown code: $(Int(code))"
end

function _read_exact!(conn::TCP.Conn, n::Integer)::Vector{UInt8}
    count = Int(n)
    count < 0 && throw(ArgumentError("read size must be >= 0"))
    buf = Vector{UInt8}(undef, count)
    got = readbytes!(conn, buf, count; all = true)
    got == count || throw(EOFError())
    return buf
end

function _parse_decimal_port(text::String)::Union{Nothing, UInt16}
    isempty(text) && return nothing
    n = 0
    for ch in text
        '0' <= ch <= '9' || return nothing
        n = 10 * n + Int(ch - '0')
        n > 0xffff && return nothing
    end
    return UInt16(n)
end

function _parse_target(address::AbstractString)::Tuple{String, UInt16}
    text = String(address)
    host, port_text = try
        HostResolvers.split_host_port(text)
    catch err
        ex = err::Exception
        ex isa HostResolvers.AddressError || rethrow(ex)
        throw(TargetAddressError("invalid SOCKS target address", text))
    end
    isempty(host) && throw(TargetAddressError("SOCKS target host must not be empty", text))
    port = _parse_decimal_port(port_text)
    port === nothing && throw(TargetAddressError("invalid SOCKS target port", text))
    port == 0 && throw(TargetAddressError("SOCKS target port out of range", text))
    # A remote proxy cannot resolve a client-local zone, so zone-scoped IPv6
    # literals get a specific error up front; '%' never appears in a valid IP
    # literal (_parse_ipv6_literal rejects zones) or FQDN.
    occursin('%', host) && throw(TargetAddressError("SOCKS target host must not contain a zone", text))
    if HostResolvers._parse_ipv4_literal(host) === nothing && HostResolvers._parse_ipv6_literal(host) === nothing
        length(codeunits(host)) <= 255 || throw(TargetAddressError("SOCKS target FQDN is too long", text))
        # Bracketed-but-invalid IPv6 literals must not leak to the proxy as a
        # domain name; ':' never appears in a valid FQDN.
        occursin(':', host) &&
            throw(TargetAddressError("SOCKS target host must be an IP literal or hostname", text))
    end
    return host, port
end

@inline function _append_port!(buf::Vector{UInt8}, port::UInt16)::Nothing
    push!(buf, UInt8(port >> 8))
    push!(buf, UInt8(port & 0x00ff))
    return nothing
end

function _append_target!(buf::Vector{UInt8}, host::String, port::UInt16, address::String)::Nothing
    ip4 = HostResolvers._parse_ipv4_literal(host)
    if ip4 !== nothing
        push!(buf, _ADDR_IPV4)
        append!(buf, ip4::NTuple{4, UInt8})
        _append_port!(buf, port)
        return nothing
    end
    ip6 = HostResolvers._parse_ipv6_literal(host)
    if ip6 !== nothing
        push!(buf, _ADDR_IPV6)
        append!(buf, ip6::NTuple{16, UInt8})
        _append_port!(buf, port)
        return nothing
    end
    host_bytes = codeunits(host)
    n = length(host_bytes)
    n <= 255 || throw(TargetAddressError("SOCKS target FQDN is too long", address))
    push!(buf, _ADDR_FQDN)
    push!(buf, UInt8(n))
    append!(buf, host_bytes)
    _append_port!(buf, port)
    return nothing
end

function _read_bound_addr!(conn::TCP.Conn, atyp::UInt8)::BoundAddr
    if atyp == _ADDR_IPV4
        data = _read_exact!(conn, 6)
        host = string(data[1], ".", data[2], ".", data[3], ".", data[4])
        port = (UInt16(data[5]) << 8) | UInt16(data[6])
        return BoundAddr(host, port)
    elseif atyp == _ADDR_IPV6
        data = _read_exact!(conn, 18)
        ip = (
            data[1], data[2], data[3], data[4],
            data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12],
            data[13], data[14], data[15], data[16],
        )
        port = (UInt16(data[17]) << 8) | UInt16(data[18])
        return BoundAddr(TCP._format_ipv6(ip), port)
    elseif atyp == _ADDR_FQDN
        len = Int(_read_exact!(conn, 1)[1])
        data = _read_exact!(conn, len + 2)
        host = String(data[1:len])
        port = (UInt16(data[len + 1]) << 8) | UInt16(data[len + 2])
        return BoundAddr(host, port)
    end
    throw(ProtocolError("unknown SOCKS address type $(Int(atyp))"))
end

@inline function _auth_enabled(username)::Bool
    return username !== nothing
end

function _validate_credentials(
        username::Union{Nothing, AbstractString},
        password::Union{Nothing, AbstractString},
    )::Nothing
    if username === nothing
        password === nothing || throw(AuthenticationError("SOCKS password provided without a username"))
        return nothing
    end
    username_len = length(codeunits(username))
    username_len >= 1 || throw(AuthenticationError("SOCKS username must not be empty"))
    username_len <= 255 || throw(AuthenticationError("SOCKS username is too long"))
    if password !== nothing
        length(codeunits(password)) <= 255 || throw(AuthenticationError("SOCKS password is too long"))
    end
    return nothing
end

function _write_greeting!(conn::TCP.Conn, has_auth::Bool)::Nothing
    if has_auth
        write(conn, UInt8[_VERSION5, 0x02, _AUTH_NO_AUTH, _AUTH_USERNAME_PASSWORD])
    else
        write(conn, UInt8[_VERSION5, 0x01, _AUTH_NO_AUTH])
    end
    return nothing
end

function _negotiate_auth!(
        conn::TCP.Conn,
        username::Union{Nothing, AbstractString},
        password::Union{Nothing, AbstractString},
    )::Nothing
    has_auth = _auth_enabled(username)
    _write_greeting!(conn, has_auth)
    reply = _read_exact!(conn, 2)
    reply[1] == _VERSION5 || throw(ProtocolError("unexpected SOCKS version $(Int(reply[1]))"))
    method = reply[2]
    method == _AUTH_NO_ACCEPTABLE && throw(AuthenticationError("no acceptable SOCKS authentication methods"))
    if method == _AUTH_NO_AUTH
        return nothing
    end
    if method == _AUTH_USERNAME_PASSWORD && has_auth
        _authenticate_username_password!(conn, String(username::AbstractString), password === nothing ? "" : String(password::AbstractString))
        return nothing
    end
    throw(AuthenticationError("unsupported SOCKS authentication method $(Int(method))"))
end

function _authenticate_username_password!(conn::TCP.Conn, username::String, password::String)::Nothing
    username_bytes = codeunits(username)
    password_bytes = codeunits(password)
    isempty(username_bytes) && throw(AuthenticationError("SOCKS username must not be empty"))
    length(username_bytes) <= 255 || throw(AuthenticationError("SOCKS username is too long"))
    length(password_bytes) <= 255 || throw(AuthenticationError("SOCKS password is too long"))
    request = UInt8[_AUTH_USERNAME_PASSWORD_VERSION, UInt8(length(username_bytes))]
    append!(request, username_bytes)
    push!(request, UInt8(length(password_bytes)))
    append!(request, password_bytes)
    write(conn, request)
    reply = _read_exact!(conn, 2)
    reply[1] == _AUTH_USERNAME_PASSWORD_VERSION || throw(AuthenticationError("invalid SOCKS username/password auth version"))
    reply[2] == _AUTH_STATUS_SUCCEEDED || throw(AuthenticationError("SOCKS username/password authentication failed"))
    return nothing
end

function _send_connect!(
        conn::TCP.Conn,
        target_address::String,
        host::String,
        port::UInt16,
    )::BoundAddr
    request = UInt8[_VERSION5, _CMD_CONNECT, 0x00]
    _append_target!(request, host, port, target_address)
    write(conn, request)
    reply = _read_exact!(conn, 4)
    reply[1] == _VERSION5 || throw(ProtocolError("unexpected SOCKS version $(Int(reply[1]))"))
    reply[2] == _STATUS_SUCCEEDED || throw(ReplyError(reply[2], _reply_message(reply[2])))
    reply[3] == 0x00 || throw(ProtocolError("non-zero SOCKS reserved field"))
    return _read_bound_addr!(conn, reply[4])
end

"""
    connect!(conn, target_address; username=nothing, password=nothing, deadline_ns=0)

Perform a SOCKS5 (RFC 1928) CONNECT handshake over `conn` and return the proxy
bound address as a `BoundAddr`. On success, `conn` is the established stream to
`target_address`, a `"host:port"` (or `"[ipv6]:port"`) string.

When `username` is provided, username/password authentication (RFC 1929) is
offered alongside no-auth and performed if the proxy selects it. `username`
must be 1-255 bytes, `password` at most 255 bytes, and a `password` without a
`username` is rejected.

A nonzero `deadline_ns` (absolute monotonic nanoseconds on the `time_ns()`
clock) sets the read and write deadlines on `conn` for the duration of the
handshake and clears them on exit, overwriting any deadlines previously set on
`conn`. With `deadline_ns == 0`, existing deadlines are left untouched.

Target and credential validation failures (`TargetAddressError`,
`AuthenticationError`) are thrown before any proxy I/O. During the handshake,
`AuthenticationError`, `ReplyError`, `ProtocolError`, `EOFError`, or
`TCP.DeadlineExceededError` may be thrown; after any error the proxy stream
state is indeterminate and `conn` should be closed.
"""
function connect!(
        conn::TCP.Conn,
        target_address::AbstractString;
        username::Union{Nothing, AbstractString}=nothing,
        password::Union{Nothing, AbstractString}=nothing,
        deadline_ns::Integer=0,
    )::BoundAddr
    deadline = Int64(deadline_ns)
    target = String(target_address)
    host, port = _parse_target(target)
    _validate_credentials(username, password)
    if deadline != 0
        TCP.set_deadline!(conn, deadline)
    end
    try
        _negotiate_auth!(conn, username, password)
        return _send_connect!(conn, target, host, port)
    finally
        if deadline != 0
            TCP.set_deadline!(conn, Int64(0))
        end
    end
end

end
