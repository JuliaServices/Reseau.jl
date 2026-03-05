"""
    HTTP

HTTP protocol layer built on top of `TCP` and `TLS`.

Includes:
- core HTTP request/response/header/body types
- HTTP/1 parser/serializer
- HPACK + HTTP/2 framing/client/server
- high-level client and server interfaces
"""
module HTTP

include("70_http_core.jl")
include("71_http1.jl")
include("72_hpack.jl")
include("73_http2.jl")
include("74_http2_client.jl")
include("75_http2_server.jl")
include("76_http_client.jl")
include("77_http_server.jl")

end
