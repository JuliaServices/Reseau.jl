# Struct Type Parameterization Tracking

All structs across AwsIO and AwsHTTP that have non-concrete field types (`::Any`,
`::Union{ParametricType, Nothing}`, `::Function`, etc.) and need type parameters.

## Pattern Reference

```julia
# Before (non-concrete fields → dynamic dispatch at runtime)
struct Foo
    callback::Any
    connection::Union{ChannelSlot, Nothing}  # ChannelSlot is parametric
    user_data::Any
end

# After (concrete fields → zero-cost access)
struct Foo{CB, C <: Union{ChannelSlot, Nothing}, UD}
    callback::CB
    connection::C
    user_data::UD
end
```

Callback aliases (`ChannelOnSetupCompletedFn`, `SocketOnReadableFn`, etc.) are all
`const = Function`, so `Union{SuchAlias, Nothing}` is non-concrete and needs parameterization.

## Legend

- `[ ]` — needs conversion
- `[x]` — done (all feasible fields parameterized)
- `[-]` — skipped (all fields are late-init, no parameterization possible)
- `[p]` — partial (some fields parameterized, late-init fields left as `::Any`)

---

## AwsIO

### src/io/channel.jl

- [ ] **ChannelOptions{EL}** (line 15) — already has `{EL}`, needs more params
  - `on_setup_completed::Union{ChannelOnSetupCompletedFn, Nothing}`
  - `on_shutdown_completed::Union{ChannelOnShutdownCompletedFn, Nothing}`
  - `setup_user_data::Any`
  - `shutdown_user_data::Any`

- [ ] **ChannelTaskContext** (line 43) — no params
  - `channel::Any`
  - `task::Any`

- [ ] **ChannelTask** (line 48) — no params
  - `wrapper_task::ScheduledTask` (ScheduledTask{F,Ctx} is parametric)
  - `task_fn::Function` (abstract)
  - `arg::Any`
  - Note: `ctx::ChannelTaskContext` will need updating after ChannelTaskContext is parameterized

- [ ] **Channel{EL, SlotRef}** (line 230) — already has `{EL, SlotRef}`, needs more params
  - `message_pool::Union{MessagePool, Nothing}`
  - `on_setup_completed::Union{ChannelOnSetupCompletedFn, Nothing}`
  - `on_shutdown_completed::Union{ChannelOnShutdownCompletedFn, Nothing}`
  - `setup_user_data::Any`
  - `shutdown_user_data::Any`
  - `statistics_handler::Union{StatisticsHandler, Nothing}`
  - `statistics_task::Union{ScheduledTask, Nothing}` (ScheduledTask is parametric)
  - `statistics_list::ArrayList{Any}` → should be `ArrayList{T}`
  - `pending_tasks::IdDict{Any, Bool}` → key type should be concrete
  - `window_update_task::ChannelTask` (will become parametric)
  - `shutdown_task::ChannelTask` (will become parametric)

- [ ] **ChannelSetupArgs** (line 374) — no params
  - `channel::Channel` (Channel is parametric)

- [ ] **ChannelShutdownWriteArgs** (line 1008) — no params
  - `slot::ChannelSlot` (ChannelSlot is parametric)

### src/io/tls_channel_handler.jl

- [x] **TlsCtxPkcs11Options{PL}** — parameterized `pkcs11_lib::PL`

- [x] **Pkcs11KeyOpState{PL}** — parameterized `pkcs11_lib::PL`

- [-] **TlsContextOptions** — both `ctx_options_extension` and `custom_key_op_handler` are late-init (starts nothing, mutated later). Cannot parameterize.

- [ ] **S2nTlsHandler{SlotRef}** (line 1764) — has `{SlotRef}`, needs more params
  - `shared::TlsHandlerShared{Any}` → should use concrete param
  - `ctx::Union{TlsContext, Nothing}` (TlsContext{Impl} is parametric)
  - `s2n_ctx::Union{S2nTlsCtx, Nothing}`
  - `latest_message_on_completion::Any`
  - `latest_message_completion_user_data::Any`
  - `on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing}`
  - `on_data_read::Union{TlsOnDataReadFn, Nothing}`
  - `on_error::Union{TlsOnErrorFn, Nothing}`
  - `user_data::Any`

- [ ] **SecureTransportTlsHandler{SlotRef}** (line 3001) — has `{SlotRef}`, needs more params
  - `shared::TlsHandlerShared{Any}` → should use concrete param
  - `ctx_obj::Union{TlsContext, Nothing}` (TlsContext{Impl} is parametric)
  - `latest_message_on_completion::Any`
  - `latest_message_completion_user_data::Any`
  - `on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing}`
  - `on_data_read::Union{TlsOnDataReadFn, Nothing}`
  - `on_error::Union{TlsOnErrorFn, Nothing}`
  - `user_data::Any`

### src/io/host_resolver.jl

- [ ] **PendingCallback** (line 65) — no params
  - `user_data::Any`

- [ ] **HostResolverConfig** (line 71) — no params
  - `clock_override::Union{Function, Nothing}`

- [ ] **HostResolutionConfig** (line 81) — no params
  - `impl::Union{Function, Nothing}`
  - `impl_data::Any`

- [ ] **HostEntry** (line 172) — no params
  - `resolver::DefaultHostResolver` (parametric)
  - `on_host_purge_complete::Union{Function, Nothing}`
  - `on_host_purge_complete_user_data::Any`
  - Note: also has `pending_callbacks::Deque{PendingCallback}` — once PendingCallback
    becomes parametric, this becomes non-concrete too. Need guidance on ordering.

### src/io/retry_strategy.jl

- [x] **ExponentialBackoffConfig{FR, FRI, UD}** — parameterized all three fields

### src/io/apple_nw_socket.jl

- [ ] **NWParametersContext** (line 87) — no params
  - `socket::Any`

- [ ] **NWSocket** (line 92) — no params, many non-concrete fields
  - `on_readable_user_data::Any`
  - `connect_result_user_data::Any`
  - `listen_accept_started_user_data::Any`
  - `close_user_data::Any`
  - `cleanup_user_data::Any`
  - `event_loop::Union{EventLoop, Nothing}` (EventLoop is parametric)
  - `timeout_task::Union{ScheduledTask, Nothing}` (ScheduledTask is parametric)
  - `tls_ctx::Union{Any, Nothing}`
  - `base_socket::Union{Socket, Nothing}` (Socket is parametric)
  - Callback fields: `on_readable`, `on_connection_result`, `on_accept_started`,
    `on_close_complete`, `on_cleanup_complete` — all `Union{SomeFn, Nothing}`

- [x] **NWSendContext{UD}** — parameterized `user_data::UD`

### src/io/socket_channel_handler.jl

- [ ] **SocketChannelHandler{S, SlotRef}** (line 10) — already has `{S, SlotRef}`
  - `read_task_storage::ChannelTask` — ChannelTask will become parametric
  - `shutdown_task_storage::ChannelTask` — same

### src/io/channel_bootstrap.jl

- [x] **ClientBootstrapOptions{..., HRC}** — added `HRC <: Union{HostResolutionConfig, Nothing}` for `host_resolution_config`

- [x] **ClientBootstrap{..., HRC}** — added matching `HRC` param, updated constructor

- [ ] **SocketConnectionRequest** — already has many type params, audit remaining `::Any` fields

- [ ] **ServerBootstrapOptions** — already has many type params, audit remaining `::Any` fields

- [ ] **ServerBootstrap** — already has many type params, audit remaining `::Any` fields

### src/io/event_loop.jl

- [ ] **EventLoopGroupOptions{S, C, Clock}** (line 82) — already has params
  - `shutdown_complete_user_data::Any`

### src/io/retry_strategy.jl

- [p] **RetryToken{S, U, BL}** — added `BL <: Union{Nothing, EventLoop}` for `bound_loop`. `scheduled_retry_task` and `on_retry_ready` are late-init.

- [ ] **StandardRetryToken{ELG, U}** (line 584) — already has `{ELG, U}`
  - Same pattern as RetryToken — `bound_loop`, `scheduled_retry_task`, `on_retry_ready`

### src/io/socket.jl

- [ ] **Socket{V, I, H, FR, UR, FC, FA, UA}** (line 260) — already has many params
  - `event_loop::Union{EventLoop, Nothing}` (EventLoop is parametric)
  - `impl::Union{I, Nothing}` — is this concrete given `I` is a param?

---

## AwsHTTP

### src/h1_stream.jl

- [x] **HttpMakeRequestOptions{UD, FRH, FRHBD, FRB, FM, FC, FD, HP, FH2C}** — all fields parameterized (immutable struct)

- [x] **HttpRequestHandlerOptions{SC, UD, FRH, FRHBD, FRB, FRD, FC, FD}** — all fields parameterized (immutable struct)

- [x] **H1Stream{OC, UD, FIH, FIHBD, FIB, FM, FC, FD, FRD}** — all callbacks and owning_connection parameterized. `encoder_message::Union{H1EncoderMessage, Nothing}` is late-init.

### src/h1_connection.jl

- [p] **H1Connection{FSD, FPT, FCHI}** — parameterized `on_shutdown::FSD`, `proxy_request_transform::FPT`, `on_channel_handler_installed::FCHI`. Late-init: `user_data::Any` (reassigned via `http_connection_configure_server`), `slot` (set by `channel_slot_set_handler!`), `outgoing_stream`/`incoming_stream` (stream lifecycle).

### src/h1_encoder.jl

- [p] **H1Chunk{FC, UD}** — parameterized `on_complete::FC`, `user_data::UD`. `data::Any` is late-init (set to `nothing` on destroy).

- [-] **H1EncoderMessage** — `body` and `trailer` are both late-init. Cannot parameterize.

- [-] **H1Encoder** — `message`, `current_chunk`, `current_stream` all late-init. Cannot parameterize.

### src/h1_decoder.jl

- [x] **H1DecoderVtable{FH, FB, FReq, FResp, FD}** — all 5 callback fields parameterized (immutable struct)

- [x] **H1DecoderParams{UD, VT <: H1DecoderVtable}** — parameterized `user_data::UD`, `vtable::VT`

- [p] **H1Decoder{VT <: H1DecoderVtable, UD}** — parameterized `vtable::VT`, `user_data::UD`. `logging_id::Any` is late-init.

### src/h2_connection.jl

- [x] **H2PendingPing{FC, UD}** — all fields parameterized

- [x] **H2PendingSettings{FC, UD}** — all fields parameterized

- [p] **H2Connection{FSD}** — parameterized `on_shutdown::FSD`. Late-init: `user_data::Any` (reassigned via `http_connection_configure_server`), `on_goaway_received::Any` and `on_remote_settings_change::Any` (reassigned after construction), `slot` (set by `channel_slot_set_handler!`). `active_streams::Dict{UInt32, Any}` left as-is (heterogeneous H2Stream types).

### src/h2_stream.jl

- [x] **H2StreamDataWrite{FC, UD}** — all fields parameterized

- [p] **H2Stream{OC, UD, FIH, FIHBD, FIB, FM, FC, FIPP}** — parameterized connection, callbacks, and user_data. `on_destroy::Any` is late-init (reassigned after construction in tests).

### src/connection.jl

- [x] **HttpClientConnectionOptions{BS, SO, TLS, ALPN, UD, FS, FSD, H2O, REL, PO, MO}** — all fields parameterized (immutable struct)

### src/client_bootstrap.jl

- [-] **_HttpClientBootstrap** — `connection::Any` is late-init (set after construction). Cannot parameterize.

### src/request_response.jl

- [-] **HttpMessage** — `body_stream::Any` is late-init. Cannot parameterize.

### src/server.jl

- [x] **HttpServerConnectionOptions{CUD, FIR, FH2C, FSD}** — all fields parameterized (immutable struct)

- [x] **HttpServerOptions{SUD, FIC, FDC}** — all fields parameterized (immutable struct)

- [ ] **HttpServer** — `connections::Vector{Any}` holds heterogeneous connection types. Needs further analysis.

### src/connection_monitor.jl

- [x] **HttpConnectionMonitor{FU, UD}** — parameterized `on_unhealthy::FU`, `user_data::UD`

### src/connection_manager.jl

- [x] **IdleConnection{C}** — parameterized `connection::C`

- [x] **PendingAcquisition{CB, UD}** — parameterized `callback::CB`, `user_data::UD`

- [x] **HttpConnectionManagerOptions{SUD, SCB, FCS}** — all fields parameterized (immutable struct)

### src/proxy.jl

- [x] **HttpProxyNegotiatorForwardingVtable{FRT}** — parameterized `forward_request_transform::FRT`

- [x] **HttpProxyNegotiatorTunnellingVtable{FCRT, FIH, FS, FIB, FRD}** — all fields parameterized

- [x] **HttpProxyNegotiator{Impl, FV, TV}** — parameterized all three fields with bounds on vtable types

- [x] **HttpProxyStrategyVtable{FCN}** — parameterized `create_negotiator::FCN`

- [x] **HttpProxyStrategy{VT, Impl}** — parameterized vtable and impl

- [x] **HttpProxyOptions{PS}** — parameterized `proxy_strategy::PS`

- [x] **HttpProxyConfig{PS}** — parameterized `proxy_strategy::PS`

### src/websocket.jl

- [x] **WsDecoder{FF, FP, UD}** — all callback and user_data fields parameterized

- [x] **WebSocket{UD, Dec, FBegin, FPayload, FComplete, FShutdown}** — all fields parameterized

### src/h2_stream_manager.jl

- [x] **H2SmConnection{C}** — parameterized `connection::C`

- [p] **H2SmPendingStreamAcquisition{RO, CB, UD}** — parameterized `request_options`, `callback`, `user_data`. `sm_connection::Union{H2SmConnection, Nothing}` is late-init.

- [x] **Http2StreamManagerOptions{SUD, SCB, FCS}** — all fields parameterized (immutable struct)

---

## Structs Already Properly Parameterized (no changes needed)

### AwsIO
- `ArrayList{T}`, `PriorityQueue{T, Less}`, `Deque{T}`, `LRUCache{K,V,HE}`,
  `FIFOCache{K,V,HE}`, `LIFOCache{K,V,HE}`, `HashTable{K,V,HE,...}`,
  `SmallRegistry{K,V}`, `SmallList{T}`, `LinkedHashTable{K,V}`, `ByteString`,
  `HashEq{H,Eq}`, `Future{T}`, `Promise{T}`, `FutureWaiter{F,U}`,
  `ScheduledTask{F,Ctx}`, `TaskFn{F,Ctx}`, `TaskScheduler{Less}`,
  `shutdown_callback_options{F,U}`, `EventLoopLocalObject{T,OnRemoved}`,
  `EventLoopOptions{Clock}`, `EventLoop{Impl,LD,Clock}`, `EventLoopGroup{EL,S}`,
  `TlsContext{Impl}`, `TlsKeyOperation{F,UD,Handler}`,
  `CustomKeyOpHandler{F,UD}`, `TlsByoCryptoSetupOptions{NewFn,StartFn,UD}`,
  `AlpnHandler{F,U,SlotRef}`, `PassthroughHandler{SlotRef}`,
  `ChannelHandlerBase{V,Impl,SlotRef}`, `ChannelSlot{H,C,SlotRef}`,
  `PosixSocket{FC,UC,FK,UK}`, `PosixSocketConnectArgs{S}`,
  `SocketWriteRequest{F,U}`, `SocketConnectOptions{E,T,F,U}`,
  `SocketBindOptions{E,T,U}`, `SocketListenerOptions{FR,UR,FS,US}`,
  `Utf8Decoder{F}`, `LoggerPipeline{F,C,W}`, `BackgroundChannel{W}`,
  `AsyncInputStream{FRead,FDestroy,Impl}`, `PipeReadEnd{U}`,
  `run_command_options{S}`, `XmlParserOptions{F}`, `CliSubcommand{F}`,
  `ThreadHandle{F}`, `FileLogWriter{I}`

### AwsHTTP
- `RandomAccessSet{T}`

---

## Notes for Guidance

1. **ChannelTask cascade**: ChannelTask is used pervasively as a field type across both
   packages. Once it gets type params, every struct containing `::ChannelTask` needs
   updating. Consider doing ChannelTask early.

2. **NWSocket**: Has ~15 non-concrete fields. This will get many type parameters.
   Is there a threshold where we should consider a different approach (e.g., splitting
   the struct or using an inner options struct)?

3. **Deque{PendingCallback}** in HostEntry: Once PendingCallback becomes
   `PendingCallback{UD}`, `Deque{PendingCallback}` becomes non-concrete.
   The Deque needs a concrete element type. Possible approaches:
   - Parameterize HostEntry over `PC <: PendingCallback`
   - Use `Deque{PendingCallback{Any}}` explicitly (still concrete, type params fixed)

4. **H1Connection / H2Connection as AbstractChannelHandler subtypes**: Adding type params
   to these changes the concrete type, which may affect dispatch on
   `AbstractChannelHandler`. Verify all method dispatch still works.

5. **Dict{UInt32, Any} in H2Connection**: The values are `H2Stream`. Once H2Stream
   gets type params, should this become `Dict{UInt32, H2Stream{...}}` or
   `Dict{UInt32, T} where T <: H2Stream`?

6. **channel_bootstrap.jl structs (ClientBootstrap, ServerBootstrap, etc.)**: These
   already have many type parameters. Need to audit whether they have remaining
   `::Any` fields that were missed.
