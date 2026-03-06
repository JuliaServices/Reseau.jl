using Reseau
const ND = Reseau.HostResolvers
const NC = Reseau.TCP

const _HAS_HTTP = isdefined(Reseau, :HTTP)
const HT = _HAS_HTTP ? getfield(Reseau, :HTTP) : nothing

# Drive inference through the exact signatures repeatedly named in the Windows nightly logs.
Base.return_types(ND.connect, Tuple{ND.HostResolver{ND.SystemResolver}, String, String})
Base.return_types(NC.connect_tcp_fd!, Tuple{NC.SocketAddrV4})

if _HAS_HTTP
    http_mod = getfield(Reseau, :HTTP)
    Base.return_types(getfield(http_mod, :roundtrip!), Tuple{HT.Transport, String, HT.Request{HT.EmptyBody}})
    Base.return_types(getfield(http_mod, :roundtrip!), Tuple{HT.Transport, String, HT.Request{HT.BytesBody}})
    Base.return_types(getfield(http_mod, :do!), Tuple{HT.Client, String, HT.Request{HT.EmptyBody}})
    Base.return_types(getfield(http_mod, :do!), Tuple{HT.Client, String, HT.Request{HT.BytesBody}})
end
