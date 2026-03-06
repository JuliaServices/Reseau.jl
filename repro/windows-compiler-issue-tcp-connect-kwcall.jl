using Reseau
const ND = Reseau.HostResolvers
const NC = Reseau.TCP
const KW = NamedTuple{(:local_addr, :connect_deadline_ns, :cancel_state), Tuple{Nothing, Int64, ND.DNSRaceState}}
Base.return_types(Core.kwcall, Tuple{KW, typeof(NC.connect_tcp_fd!), NC.SocketAddrV4})
