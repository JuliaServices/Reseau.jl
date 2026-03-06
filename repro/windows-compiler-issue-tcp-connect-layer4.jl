using Reseau
const NC = Reseau.TCP
Base.return_types(NC.connect_tcp_fd!, Tuple{NC.SocketAddrV4})
