"""
    HTTP

HTTP protocol layer built on top of `TCP` and `TLS`.

The code is split roughly the same way Go's `net/http`, `x/net/http2`, and
supporting wire-format packages are split:
- `7_0_http_core.jl` defines protocol-neutral request, response, header, body,
  and cancellation types shared by client and server code.
- `7_1_http1.jl` implements HTTP/1.1 parsing and serialization.
- `7_2_hpack.jl` and `7_3_http2.jl` implement the HPACK and HTTP/2 wire layers.
- `7_4_http2_client.jl`, `7_5_http2_server.jl`, `7_6_http_client.jl`,
  `7_6_http_stream.jl`, `7_6_http_sse.jl`, and `7_7_http_server.jl` build
  higher-level client/server behavior on top.

This module exports both the low-level wire APIs and the convenience client and
server entry points. Most public functions either return one of the shared
`Request`/`Response`/`Headers` types or mutate a caller-supplied transport/body
object in place.
"""
module HTTP

include("7_0_http_core.jl")
include("7_1_http1.jl")
include("7_2_hpack.jl")
include("7_3_http2.jl")
include("7_4_http2_client.jl")
include("7_5_http2_server.jl")
include("7_6_http_sniff.jl")
include("7_6_http_forms.jl")
include("7_6_http_cookies.jl")
include("7_6_http_proxy.jl")
include("7_6_http_request_bodies.jl")
include("7_6_http_client.jl")
include("7_6_http_stream.jl")
include("7_6_http_sse.jl")
include("7_7_http_server.jl")

end
