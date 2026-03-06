"""
    HTTP

HTTP protocol layer built on top of `TCP` and `TLS`.

The code is split roughly the same way Go's `net/http`, `x/net/http2`, and
supporting wire-format packages are split:
- `70_http_core.jl` defines protocol-neutral request, response, header, body,
  and cancellation types shared by client and server code.
- `71_http1.jl` implements HTTP/1.1 parsing and serialization.
- `72_hpack.jl` and `73_http2.jl` implement the HPACK and HTTP/2 wire layers.
- `74_http2_client.jl`, `76_http_client.jl`, `75_http2_server.jl`, and
  `77_http_server.jl` build higher-level client/server behavior on top.

This module exports both the low-level wire APIs and the convenience client and
server entry points. Most public functions either return one of the shared
`Request`/`Response`/`Headers` types or mutate a caller-supplied transport/body
object in place.
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
