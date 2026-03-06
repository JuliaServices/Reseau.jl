using Reseau
const NC = Reseau.TCP
Base.return_types(getfield(NC, Symbol("_wait_connect_complete!")), Tuple{NC.FD, NC.SocketAddrV4})
