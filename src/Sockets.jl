module Sockets

# A libuv-free, stdlib-like sockets surface built on Reseau's socket + channel + TLS stack.
# This module is intended to be a drop-in replacement for `Sockets` for the TCP + LOCAL
# (named pipes / unix domain sockets) subset.

include("sockets/ipaddr.jl")
include("sockets/dns.jl")
include("sockets/tcp.jl")

end # module Sockets

