using Reseau
const ND = Reseau.HostResolvers
Base.return_types(ND.connect, Tuple{ND.HostResolver{ND.SystemResolver}, String, String})
