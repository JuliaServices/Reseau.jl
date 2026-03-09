# HTTP client proxy planning, env parsing, and no_proxy matching helpers.
export ProxyConfig
export NoProxy
export ProxyURL
export ProxyFromEnvironment

using Base64
using EnumX
using ..Reseau.HostResolvers

abstract type AbstractProxySelector end

struct _NoProxyIPRule{N}
    ip::NTuple{N, UInt8}
    port::Int32
end

struct _NoProxyCIDRRule{N}
    network::NTuple{N, UInt8}
    prefix_len::UInt8
end

struct _NoProxyDomainRule
    domain::String
    subdomains_only::Bool
    port::Int32
end

mutable struct NoProxy
    matches_all::Bool
    ipv4::Vector{_NoProxyIPRule{4}}
    ipv6::Vector{_NoProxyIPRule{16}}
    ipv4_cidrs::Vector{_NoProxyCIDRRule{4}}
    ipv6_cidrs::Vector{_NoProxyCIDRRule{16}}
    domains::Vector{_NoProxyDomainRule}
end

struct ProxyConfig <: AbstractProxySelector
    url::String
    secure::Bool
    address::String
    authorization::Union{Nothing, String}
    no_proxy::Union{Nothing, NoProxy}
end

struct _EnvironmentProxySelector <: AbstractProxySelector
    http_proxy::Union{Nothing, ProxyConfig}
    https_proxy::Union{Nothing, ProxyConfig}
    all_proxy::Union{Nothing, ProxyConfig}
    no_proxy::Union{Nothing, NoProxy}
end

@enumx _ProxyPlanMode::UInt8 begin
    DIRECT = 0
    HTTP_FORWARD = 1
    HTTP_TUNNEL = 2
    SOCKS5 = 3
    SOCKS5H = 4
end

struct _ProxyPlan
    mode::_ProxyPlanMode.T
    proxy::Union{Nothing, ProxyConfig}
    first_hop_key::String
end

NoProxy() = NoProxy(false, _NoProxyIPRule{4}[], _NoProxyIPRule{16}[], _NoProxyCIDRRule{4}[], _NoProxyCIDRRule{16}[], _NoProxyDomainRule[])

function _normalize_proxy_host(host::AbstractString)::String
    normalized = lowercase(String(host))
    while !isempty(normalized) && last(normalized) == '.'
        normalized = normalized[1:prevind(normalized, lastindex(normalized))]
    end
    return normalized
end

function _split_host_port_optional(value::AbstractString)::Tuple{String, Int32}
    text = strip(String(value))
    isempty(text) && return "", Int32(-1)
    if startswith(text, "[")
        close_idx = findfirst(']', text)
        close_idx === nothing && return text, Int32(-1)
        if close_idx < lastindex(text) && @inbounds text[nextind(text, close_idx)] == ':'
            host = String(SubString(text, firstindex(text), close_idx))
            port_text = String(SubString(text, nextind(text, nextind(text, close_idx)), lastindex(text)))
            parsed = tryparse(Int, port_text)
            return host, parsed === nothing ? Int32(-1) : Int32(parsed)
        end
        return text, Int32(-1)
    end
    colon_count = count(==(':'), text)
    if colon_count == 1
        host, port = HostResolvers.split_host_port(text)
        parsed = tryparse(Int, port)
        return host, parsed === nothing ? Int32(-1) : Int32(parsed)
    end
    return text, Int32(-1)
end

function _port_matches(rule_port::Int32, port::Int32)::Bool
    return rule_port < 0 || rule_port == port
end

function _is_loopback_ip(ip::NTuple{4, UInt8})::Bool
    return ip[1] == UInt8(127)
end

function _is_loopback_ip(ip::NTuple{16, UInt8})::Bool
    for i in 1:15
        ip[i] == 0x00 || return false
    end
    return ip[16] == 0x01
end

function _cidr_matches(network::NTuple{N, UInt8}, prefix_len::UInt8, ip::NTuple{N, UInt8}) where {N}
    remaining = Int(prefix_len)
    for i in 1:N
        remaining <= 0 && return true
        if remaining >= 8
            network[i] == ip[i] || return false
            remaining -= 8
            continue
        end
        mask = UInt8(0xff << (8 - remaining))
        return (network[i] & mask) == (ip[i] & mask)
    end
    return true
end

function _domain_matches(host::String, rule::_NoProxyDomainRule, port::Int32)::Bool
    _port_matches(rule.port, port) || return false
    if rule.subdomains_only
        return endswith(host, "." * rule.domain)
    end
    host == rule.domain && return true
    return endswith(host, "." * rule.domain)
end

function _parse_no_proxy_entry!(matcher::NoProxy, raw_entry::AbstractString)
    entry = strip(String(raw_entry))
    isempty(entry) && return nothing
    if entry == "*"
        matcher.matches_all && return nothing
        matcher.matches_all = true
        empty!(matcher.ipv4)
        empty!(matcher.ipv6)
        empty!(matcher.ipv4_cidrs)
        empty!(matcher.ipv6_cidrs)
        empty!(matcher.domains)
        return nothing
    end
    host_text, port = _split_host_port_optional(entry)
    host_text = strip(host_text)
    isempty(host_text) && return nothing
    if occursin('/', host_text) && !occursin(':', host_text[findfirst('/', host_text):end])
        host_part, prefix_part = split(host_text, '/'; limit = 2)
        prefix = tryparse(Int, prefix_part)
        prefix === nothing && return nothing
        ip4 = HostResolvers._parse_ipv4_literal(host_part)
        if ip4 !== nothing
            0 <= prefix <= 32 || return nothing
            push!(matcher.ipv4_cidrs, _NoProxyCIDRRule{4}(ip4::NTuple{4, UInt8}, UInt8(prefix)))
            return nothing
        end
        ip6 = HostResolvers._parse_ipv6_literal(host_part)
        if ip6 !== nothing
            0 <= prefix <= 128 || return nothing
            push!(matcher.ipv6_cidrs, _NoProxyCIDRRule{16}(ip6::NTuple{16, UInt8}, UInt8(prefix)))
            return nothing
        end
        return nothing
    end
    host_for_ip = startswith(host_text, "[") && endswith(host_text, "]") ? String(SubString(host_text, nextind(host_text, firstindex(host_text)), prevind(host_text, lastindex(host_text)))) : host_text
    ip4 = HostResolvers._parse_ipv4_literal(host_for_ip)
    if ip4 !== nothing
        push!(matcher.ipv4, _NoProxyIPRule{4}(ip4::NTuple{4, UInt8}, port))
        return nothing
    end
    ip6 = HostResolvers._parse_ipv6_literal(host_for_ip)
    if ip6 !== nothing
        push!(matcher.ipv6, _NoProxyIPRule{16}(ip6::NTuple{16, UInt8}, port))
        return nothing
    end
    host = _normalize_proxy_host(startswith(host_text, "*.") ? String(SubString(host_text, 3)) : (startswith(host_text, ".") ? String(SubString(host_text, 2)) : host_text))
    isempty(host) && return nothing
    subdomains_only = startswith(host_text, ".") || startswith(host_text, "*.")
    push!(matcher.domains, _NoProxyDomainRule(host, subdomains_only, port))
    return nothing
end

function NoProxy(spec)::NoProxy
    matcher = NoProxy()
    if spec isa AbstractString
        for entry in split(String(spec), ','; keepempty = false)
            _parse_no_proxy_entry!(matcher, entry)
        end
        return matcher
    end
    if spec isa AbstractVector
        for entry in spec
            _parse_no_proxy_entry!(matcher, string(entry))
        end
        return matcher
    end
    throw(ArgumentError("unsupported no_proxy spec type $(typeof(spec)); expected String or vector-like collection"))
end

function _matches_no_proxy(matcher::NoProxy, host::AbstractString, port::Integer)::Bool
    matcher.matches_all && return true
    normalized_host = _normalize_proxy_host(host)
    isempty(normalized_host) && return false
    port32 = Int32(port)
    normalized_host == "localhost" && return true
    ipv4 = HostResolvers._parse_ipv4_literal(normalized_host)
    if ipv4 !== nothing
        _is_loopback_ip(ipv4::NTuple{4, UInt8}) && return true
        for rule in matcher.ipv4
            rule.ip == ipv4 && _port_matches(rule.port, port32) && return true
        end
        for rule in matcher.ipv4_cidrs
            _cidr_matches(rule.network, rule.prefix_len, ipv4::NTuple{4, UInt8}) && return true
        end
    end
    ipv6 = HostResolvers._parse_ipv6_literal(normalized_host)
    if ipv6 !== nothing
        _is_loopback_ip(ipv6::NTuple{16, UInt8}) && return true
        for rule in matcher.ipv6
            rule.ip == ipv6 && _port_matches(rule.port, port32) && return true
        end
        for rule in matcher.ipv6_cidrs
            _cidr_matches(rule.network, rule.prefix_len, ipv6::NTuple{16, UInt8}) && return true
        end
    end
    for rule in matcher.domains
        _domain_matches(normalized_host, rule, port32) && return true
    end
    return false
end

function _parse_proxy_url(url::AbstractString; allow_unsupported::Bool = false)::ProxyConfig
    value = strip(String(url))
    isempty(value) && throw(ArgumentError("proxy URL must not be empty"))
    if !occursin("://", value)
        value = "http://" * value
    end
    parsed = _parse_http_url(value)
    secure = parsed.secure
    scheme = secure ? "https" : "http"
    if !allow_unsupported && !(scheme == "http" || scheme == "https")
        throw(ArgumentError("unsupported proxy scheme '$scheme'"))
    end
    return ProxyConfig(parsed.url, secure, parsed.address, parsed.authorization, nothing)
end

function ProxyURL(url::AbstractString; no_proxy = nothing)::ProxyConfig
    parsed = _parse_proxy_url(url)
    matcher = no_proxy === nothing ? nothing : NoProxy(no_proxy)
    return ProxyConfig(parsed.url, parsed.secure, parsed.address, parsed.authorization, matcher)
end

function _env_proxy(names::Vararg{String})::Union{Nothing, ProxyConfig}
    for name in names
        value = get(ENV, name, "")
        isempty(strip(value)) && continue
        try
            return _parse_proxy_url(value)
        catch
            return nothing
        end
    end
    return nothing
end

function ProxyFromEnvironment()::_EnvironmentProxySelector
    matcher = let raw = get(ENV, "NO_PROXY", get(ENV, "no_proxy", ""))
        isempty(strip(raw)) ? nothing : NoProxy(raw)
    end
    return _EnvironmentProxySelector(
        _env_proxy("HTTP_PROXY", "http_proxy"),
        _env_proxy("HTTPS_PROXY", "https_proxy"),
        _env_proxy("ALL_PROXY", "all_proxy"),
        matcher,
    )
end

function _proxy_for(
        selector::Nothing,
        secure::Bool,
        host::AbstractString,
        port::Integer,
    )::Union{Nothing, ProxyConfig}
    return nothing
end

function _proxy_for(
        selector::ProxyConfig,
        secure::Bool,
        host::AbstractString,
        port::Integer,
    )::Union{Nothing, ProxyConfig}
    selector.no_proxy !== nothing && _matches_no_proxy(selector.no_proxy::NoProxy, host, port) && return nothing
    return selector
end

function _proxy_for(
        selector::_EnvironmentProxySelector,
        secure::Bool,
        host::AbstractString,
        port::Integer,
    )::Union{Nothing, ProxyConfig}
    selector.no_proxy !== nothing && _matches_no_proxy(selector.no_proxy::NoProxy, host, port) && return nothing
    if secure
        selector.https_proxy !== nothing && return selector.https_proxy::ProxyConfig
    else
        selector.http_proxy !== nothing && return selector.http_proxy::ProxyConfig
    end
    return selector.all_proxy
end

function _proxy_plan(
        selector::Union{Nothing, AbstractProxySelector},
        secure::Bool,
        address::AbstractString,
    )::_ProxyPlan
    host, port_text = HostResolvers.split_host_port(String(address))
    port = tryparse(Int, port_text)
    port === nothing && throw(ArgumentError("invalid address port in proxy planning: $address"))
    proxy = _proxy_for(selector, secure, host, port)
    if proxy === nothing
        return _ProxyPlan(_ProxyPlanMode.DIRECT, nothing, string(secure ? "https://" : "http://", address))
    end
    mode = secure ? _ProxyPlanMode.HTTP_TUNNEL : _ProxyPlanMode.HTTP_FORWARD
    return _ProxyPlan(mode, proxy::ProxyConfig, string((proxy::ProxyConfig).url, "|", secure ? "https://" : "http://", address))
end
