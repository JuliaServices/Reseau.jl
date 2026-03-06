using Reseau
const HT = Reseau.HTTP
const ND = Reseau.HostResolvers
const NC = Reseau.TCP

# Drive inference through the exact signatures repeatedly named in the Windows nightly logs.
Base.return_types(HT.roundtrip!, Tuple{HT.Transport, String, HT.Request{HT.EmptyBody}})
Base.return_types(HT.roundtrip!, Tuple{HT.Transport, String, HT.Request{HT.BytesBody}})
Base.return_types(HT.do!, Tuple{HT.Client, String, HT.Request{HT.EmptyBody}})
Base.return_types(HT.do!, Tuple{HT.Client, String, HT.Request{HT.BytesBody}})
Base.return_types(ND.connect, Tuple{ND.HostResolver{ND.SystemResolver}, String, String})
Base.return_types(NC.connect_tcp_fd!, Tuple{NC.SocketAddrV4})
