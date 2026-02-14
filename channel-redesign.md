# Channel Redesign: Closure-Based Middleware Pipeline

## Goal

Replace the current `Channel → ChannelSlot → AbstractChannelHandler` machinery with a
closure-based middleware pipeline that is:

1. **`--trim=safe` compatible** — zero dynamic dispatch; every field and call is concretely typed.
2. **Feature-complete** — 1:1 parity with existing behavior: backpressure, shutdown cascade, cross-direction writes, message pooling, event-loop integration, protocol negotiation, runtime TLS upgrade.
3. **Simple** — fewer types, fewer indirections, no linked-list traversal.

## What We're Replacing

### Current Architecture

```
Channel
  ├── first::ChannelSlot  ←→  adj_right  ←→  adj_right  ←→  last::ChannelSlot
  │     handler: SocketChannelHandler     handler: TLS     handler: App
  │
  ├── message_pool::MessagePool
  ├── event_loop::EventLoop
  ├── shutdown state machine (ChannelState enum, shutdown tasks, pending task tracking)
  └── backpressure (window_update_task, per-slot window_size, batched updates)
```

**Problems:**
- `ChannelSlot.handler::Union{AbstractChannelHandler, Nothing}` — dynamic dispatch target
- `ChannelHandlerReadCallable` etc. — erase types into `Ptr{Cvoid}`, worse for trim
- Linked-list traversal via `adj_left`/`adj_right` is an indirection the compiler can't see through
- 7+ callable wrapper types per slot for a single handler
- `Socket.handler::Union{AbstractChannelHandler, Nothing}` — another abstract field
- `TCPSocket.handler::Union{AbstractChannelHandler, Nothing}` — yet another

### Typical Pipelines (Static in Practice)

**Client TLS:** Socket → TLS → App (HTTP/1 or HTTP/2)
**Server TLS:** Socket → TLS → App
**Client plaintext:** Socket → App
**Server listener:** Socket → AcceptHandler

Only 2 runtime mutations exist (ALPN handler replacement, h2c upgrade), both are
one-shot transitions. Additionally, `tlsupgrade!` on TCPSocket inserts TLS mid-flight.
All three are handled by pipeline reconstruction (see Protocol Transitions).

## New Architecture

### Core Principle

Instead of a generic linked list of slots, each "pipeline" is a set of **closures**
that are composed at construction time. Closures in Julia are concretely typed —
a closure `() -> x` where `x::Int` has a unique compiler-generated type. This means
the entire pipeline is statically typed with zero abstract fields.

### Components

#### 1. `PipelineState` (replaces `Channel` as shared infrastructure)

```julia
mutable struct PipelineState
    event_loop::EventLoop
    message_pool::MessagePool
    channel_id::UInt64

    # Shutdown
    state::PipelineLifecycle  # ACTIVE, SHUTTING_DOWN_READ, SHUTTING_DOWN_WRITE, SHUT_DOWN
    shutdown_error_code::Int
    shutdown_pending::Bool
    shutdown_immediately::Bool
    on_setup_completed::Union{EventCallable, Nothing}
    on_shutdown_completed::Union{EventCallable, Nothing}

    # The shutdown chain (populated at pipeline construction)
    shutdown_chain::ShutdownChain

    # Backpressure
    read_back_pressure_enabled::Bool
    window_update_batch::Csize_t
    window_update_batch_emit_threshold::Csize_t  # matches channel.jl:578
    window_update_scheduled::Bool
    window_update_task::ScheduledTask
    window_update_fn::Any  # the backpressure closure chain (H2 → TLS → socket)
    downstream_window::Csize_t  # effective app-level window for threshold check

    # Stats
    read_message_count::Csize_t
    write_message_count::Csize_t

    # Task scheduling (cross-thread support)
    pending_tasks::IdDict{ScheduledTask, Bool}
    pending_tasks_lock::ReentrantLock
    cross_thread_tasks::Vector{ScheduledTask}
    cross_thread_tasks_lock::ReentrantLock
    cross_thread_tasks_scheduled::Bool
    cross_thread_task::ScheduledTask  # the singleton cross-thread dispatch task

    # Shutdown task (scheduled on event loop)
    shutdown_task::ScheduledTask
    shutdown_lock::ReentrantLock
end
```

No type parameters. No handler references. No slot pointers. Pure infrastructure.

**Cross-thread task dispatch** is replicated from the current `Channel` implementation:
- `pipeline_schedule_task_now!(ps, task)` checks if on event loop thread, schedules directly or queues to `cross_thread_tasks`
- `_pipeline_schedule_cross_thread_tasks(ps, status)` drains the queue on the event loop thread
- Tasks are tracked in `pending_tasks` and canceled on shutdown (matching `_channel_shutdown_completion_task`)

#### 2. `Socket` (replaces `SocketChannelHandler` + `Socket` + leftmost `ChannelSlot`)

The current codebase has three separate types that get merged:
- `Socket` (src/sockets/io/socket.jl) — OS socket wrapper
- `SocketChannelHandler` — reads from socket, writes to socket, bridges to channel pipeline
- The leftmost `ChannelSlot` — backpressure window for socket reads

```julia
mutable struct Socket
    # OS socket state (from current Socket)
    fd::RawFD
    socket_options::SocketOptions
    event_loop::EventLoop
    local_endpoint::SocketEndpoint
    remote_endpoint::SocketEndpoint
    is_open::Bool

    # Pipeline integration
    pipeline::PipelineState

    # Dispatch targets — see "Typed Dispatch via Function Barriers" below
    read_fn::Any     # head of read middleware chain
    write_fn::Any    # the app-facing write entry point (for protocol transitions)

    # Backpressure (from current ChannelSlot + SocketChannelHandler)
    downstream_window::Csize_t
    max_rw_size::Csize_t
    pending_read::Bool

    # Stats & lifecycle (from current SocketChannelHandler)
    stats::SocketHandlerStatistics
    shutdown_in_progress::Bool

    # Read scheduling
    read_task::ScheduledTask
end
```

##### Typed Dispatch via Function Barriers

`read_fn` and `write_fn` are typed `Any` in the struct but are always assigned a
concrete closure. Dispatch goes through function barriers that force specialization:

```julia
@inline function _socket_dispatch_read(socket::Socket, msg::IoMessage)
    (socket.read_fn::Function)(msg)
    return nothing
end
```

**Trim-safety consideration:** The `::Function` assertion narrows from `Any` to
`Function`, but `Function` is still abstract. For `--trim=safe`, we need the
compiler to see the concrete closure type at compile time. Since Socket is a
mutable struct and `read_fn` is reassigned (ALPN, h2c, tlsupgrade), we cannot
make it a type parameter.

**Resolution:** Use `@nospecialize` on the function barrier and ensure the closure
body calls concretely-typed internal functions. The dynamic dispatch at the
Socket→middleware boundary is exactly ONE dispatch point in the entire pipeline —
and it can be made trim-safe by ensuring all possible closure types are compiled
ahead of time via explicit `precompile` directives in the package. This is a
pragmatic trade-off: one controlled dispatch point vs. the current ~7 per slot.

Alternatively, if a single `Any` dispatch is unacceptable, we can use a `FunctionRef`
wrapper that stores both the closure and a cfunction pointer:

```julia
mutable struct FunctionRef
    fn::Any
    fptr::Ptr{Cvoid}  # cfunction pointer for the specific closure type
end
```

But this adds complexity. Start with the function barrier approach and validate
with `--trim=safe` before adding cfunction wrappers.

##### Socket Drives Reads

Socket is not middleware — it's the event loop callback target. The event loop says
"data available on fd", and the socket read loop runs:

```julia
function _socket_do_read(socket::Socket)
    ps = socket.pipeline

    if socket.shutdown_in_progress || ps.state != PipelineLifecycle.ACTIVE
        return nothing
    end

    downstream_window = socket.downstream_window
    max_to_read = min(downstream_window, socket.max_rw_size)
    max_to_read == 0 && return nothing

    total_read = Csize_t(0)
    last_error = 0

    while total_read < max_to_read
        iter_max = max_to_read - total_read
        msg = acquire_message!(ps.message_pool, IoMessageType.APPLICATION_DATA, iter_max)
        if msg === nothing
            last_error = ERROR_OOM
            break
        end

        local bytes_read
        try
            _, bytes_read = socket_read(socket, msg.message_data)
        catch e
            last_error = e isa ReseauError ? e.code : ERROR_UNKNOWN
            release_message!(ps.message_pool, msg)
            break
        end

        total_read += bytes_read
        socket.downstream_window = sub_size_saturating(socket.downstream_window, bytes_read)
        ps.read_message_count += 1

        try
            _socket_dispatch_read(socket, msg)
        catch e
            last_error = e isa ReseauError ? e.code : ERROR_UNKNOWN
            release_message!(ps.message_pool, msg)
            break
        end
    end

    socket.stats.bytes_read += UInt64(total_read)

    if total_read < max_to_read && last_error != 0 && last_error != ERROR_IO_READ_WOULD_BLOCK
        pipeline_shutdown!(ps, last_error)
        return nothing
    end

    # If we read max_rw_size, schedule another read (matches current re-read logic)
    if total_read == socket.max_rw_size && !socket.read_task.scheduled
        event_loop_schedule_task_now!(ps.event_loop, socket.read_task)
    end

    return nothing
end
```

##### Socket Handles Writes

Socket is the terminal write destination. Write completion releases messages and
triggers shutdown on error (matching current `_on_socket_write_complete`):

```julia
function socket_write!(socket::Socket, msg::IoMessage)
    ps = socket.pipeline

    if !socket.is_open
        _on_write_complete(socket, msg, ERROR_IO_SOCKET_CLOSED, Csize_t(0))
        return nothing
    end

    cursor = byte_cursor_from_buf(msg.message_data)
    socket_write(socket, cursor, WriteCallable((err, n) -> begin
        _on_write_complete(socket, msg, err, n)
    end))
end

function _on_write_complete(socket::Socket, msg::IoMessage, error_code::Int, bytes_written::Csize_t)
    socket.stats.bytes_written += UInt64(bytes_written)

    # Message completion callback (e.g., H1 stream tracking)
    if msg.on_completion !== nothing
        msg.on_completion(error_code)
    end

    # Release message back to pool
    release_message!(socket.pipeline.message_pool, msg)

    # Trigger shutdown on error
    if error_code != AWS_OP_SUCCESS
        pipeline_shutdown!(socket.pipeline, error_code)
    end
end
```

#### 3. TLS Middleware

TLS is the most complex middleware due to cross-direction writes (s2n send callback
fires during `s2n_recv` for key updates, alerts, and also during `s2n_negotiate`).

**Design:** TLS gets a direct reference to `socket_write!` for its protocol-level
writes. This works because s2n encrypts internally before calling the send callback —
the bytes are already ciphertext.

**S2nTlsState** holds all s2n connection state with no abstract fields:

```julia
mutable struct S2nTlsState
    connection::Ptr{Cvoid}          # s2n_connection*
    tls_options::TlsConnectionOptions
    negotiation_state::TlsNegotiationState.T
    read_state::TlsHandlerReadState.T

    # References for cross-direction and downstream dispatch
    socket::Socket              # for direct protocol writes via socket_write!
    pipeline::PipelineState     # for message pool, task scheduling

    # Backpressure — TLS tracks its own window for overhead translation
    window_size::Csize_t
    current_window_update_batch::Csize_t

    # Buffering (partial TLS records)
    input_queue::Vector{IoMessage}

    # Task scheduling
    read_task::ScheduledTask
    read_task_pending::Bool
    delayed_shutdown_task::Union{ScheduledTask, Nothing}

    # Callbacks
    on_negotiation_result::Union{EventCallable, Nothing}
    on_data_read::Union{Function, Nothing}
    latest_message_on_completion::Union{Function, Nothing}
end
```

**Construction produces two closures:**

```julia
function make_tls_middleware(
    tls_state::S2nTlsState,
    downstream_read,          # next read handler (toward app)
)
    # TLS read: decrypt, pass plaintext downstream
    tls_read_fn = let tls=tls_state, dr=downstream_read
        function(msg::IoMessage)
            _tls_on_data_received(tls, msg, dr)
        end
    end

    # TLS write: encrypt, write to socket
    tls_write_fn = let tls=tls_state
        function(msg::IoMessage)
            _tls_encrypt_and_write(tls, msg)
        end
    end

    return tls_read_fn, tls_write_fn
end
```

`_tls_encrypt_and_write` uses `tls_state.socket` to write encrypted data.
The s2n send callback uses `tls_state.socket` directly for protocol messages.

**Backpressure translation** (matches current `handler_increment_read_window` in
`s2n_tls_handler.jl:892-921`):

```julia
function make_tls_window_update_fn(tls_state::S2nTlsState, upstream_window_fn)
    return let tls=tls_state, upstream=upstream_window_fn
        function(size::Csize_t)
            # Translate plaintext window to ciphertext window with record overhead
            downstream_size = size  # what app wants
            records = cld(downstream_size, Csize_t(TLS_MAX_RECORD_SIZE))
            overhead = records * Csize_t(TLS_EST_RECORD_OVERHEAD)
            total_desired = add_size_saturating(overhead, downstream_size)

            if total_desired > tls.window_size
                update = total_desired - tls.window_size
                upstream(update)  # propagate to socket
            end

            # Schedule TLS read task if negotiation complete
            if tls.negotiation_state == TlsNegotiationState.SUCCEEDED && !tls.read_task_pending
                tls.read_task_pending = true
                event_loop_schedule_task_now!(tls.pipeline.event_loop, tls.read_task)
            end
        end
    end
end
```

#### 4. HTTP/2 Middleware

H2 needs cross-direction writes during reads (WINDOW_UPDATE, PING ACK, SETTINGS ACK,
RST_STREAM, GOAWAY). Unlike TLS, these are plaintext H2 frames that **must go through
TLS encryption**, so H2 gets a reference to `tls_write_fn`.

```julia
function make_h2_middleware(
    h2_conn::H2Connection,
    tls_write_fn,             # write closure that goes through TLS
    downstream_read,          # app-level stream dispatch
    pipeline::PipelineState,
)
    h2_read_fn = let conn=h2_conn, tw=tls_write_fn, dr=downstream_read, ps=pipeline
        function(msg::IoMessage)
            _h2_on_data_received(conn, msg, tw, dr, ps)
        end
    end

    h2_write_fn = let conn=h2_conn, tw=tls_write_fn, ps=pipeline
        function(msg::IoMessage)
            _h2_encode_and_write(conn, msg, tw, ps)
        end
    end

    return h2_read_fn, h2_write_fn
end
```

**Cross-direction writes during reads** (matches current `_h2_connection_flush_outgoing!`
at `h2_connection.jl:832-875`):

```julia
function _h2_flush_outgoing!(h2_conn::H2Connection, tls_write_fn, pipeline::PipelineState)
    # Collect connection-level frames (WINDOW_UPDATE, PING ACK, SETTINGS ACK, etc.)
    output = h2_connection_get_outgoing_frames!(h2_conn)
    stream_frames = _h2_connection_collect_stream_frames!(h2_conn)
    !isempty(stream_frames) && append!(output, stream_frames)
    isempty(output) && return nothing

    msg = acquire_message!(pipeline.message_pool, IoMessageType.APPLICATION_DATA, length(output))
    msg === nothing && return nothing
    # copy frames into msg.message_data
    buf = msg.message_data
    @inbounds for i in 1:length(output)
        buf.mem[i] = output[i]
    end
    buf.len = Csize_t(length(output))

    try
        tls_write_fn(msg)
    catch e
        release_message!(pipeline.message_pool, msg)
        e isa ReseauError || rethrow()
        pipeline_shutdown!(pipeline, e.code)
    end
end
```

**Thread-safety for cross-thread flush** (matches current `h2_connection.jl:838-842`):
If `_h2_connection_flush_outgoing!` is called from a non-event-loop thread, it must
schedule a task. The H2 middleware captures `pipeline` for this purpose.

**H2 backpressure:** H2 has its own flow control (HTTP/2 WINDOW_UPDATE frames).
The window update closure for H2 translates app-level window increments to H2
stream-level and connection-level windows:

```julia
function make_h2_window_update_fn(h2_conn::H2Connection, tls_window_fn)
    return let conn=h2_conn, upstream=tls_window_fn
        function(size::Csize_t)
            # H2 auto window management sends WINDOW_UPDATE frames
            # The actual WINDOW_UPDATE is sent via cross-direction writes in _h2_flush_outgoing!
            # Here we just propagate to TLS layer for ciphertext-level window
            upstream(size)
        end
    end
end
```

#### 5. HTTP/1.1 Middleware

H1 is simpler — mostly passthrough with request/response framing:

```julia
function make_h1_middleware(
    h1_conn::H1Connection,
    upstream_write,           # tls_write_fn or socket_write!
    downstream_read,          # app handler
    pipeline::PipelineState,
)
    h1_read_fn = let conn=h1_conn, dr=downstream_read, ps=pipeline
        function(msg::IoMessage)
            _h1_on_data_received(conn, msg, dr, ps)
        end
    end

    h1_write_fn = let conn=h1_conn, uw=upstream_write, ps=pipeline
        function(msg::IoMessage)
            _h1_encode_and_write(conn, msg, uw, ps)
        end
    end

    return h1_read_fn, h1_write_fn
end
```

### Pipeline Construction (Two-Pass)

Pipelines are built in two passes: write chain first (socket→app direction), then
read chain (app→socket direction). This avoids circular dependencies.

**Example: Client TLS + HTTP/2**

```julia
function build_tls_h2_pipeline(
    socket::Socket,
    tls_state::S2nTlsState,
    h2_conn::H2Connection,
    app_read_handler,
    pipeline::PipelineState,
)
    # === Pass 1: Write chain (app → TLS → socket) ===
    # No circular deps — socket_write! is a method, always available
    tls_write_fn = let tls=tls_state
        (msg::IoMessage) -> _tls_encrypt_and_write(tls, msg)
    end
    h2_write_fn = let conn=h2_conn, tw=tls_write_fn, ps=pipeline
        (msg::IoMessage) -> _h2_encode_and_write(conn, msg, tw, ps)
    end

    # === Pass 2: Read chain (socket → TLS → H2 → app) ===
    # Build inside-out: app_read exists, then H2 captures it, then TLS captures H2
    h2_read_fn = let conn=h2_conn, tw=tls_write_fn, dr=app_read_handler, ps=pipeline
        (msg::IoMessage) -> _h2_on_data_received(conn, msg, tw, dr, ps)
    end
    tls_read_fn = let tls=tls_state, dr=h2_read_fn
        (msg::IoMessage) -> _tls_on_data_received(tls, msg, dr)
    end

    # === Pass 3: Backpressure chain (app → H2 → TLS → socket) ===
    socket_window_fn = let sock=socket
        (size::Csize_t) -> begin
            sock.downstream_window = add_size_saturating(sock.downstream_window, size)
            _socket_trigger_read(sock)
        end
    end
    tls_window_fn = make_tls_window_update_fn(tls_state, socket_window_fn)
    h2_window_fn = make_h2_window_update_fn(h2_conn, tls_window_fn)

    # === Pass 4: Shutdown chain ===
    shutdown = build_shutdown_chain(socket, tls_state, h2_conn, pipeline)

    # === Wire it all together ===
    socket.read_fn = tls_read_fn
    socket.write_fn = h2_write_fn  # what the app uses to write
    pipeline.shutdown_chain = shutdown
    pipeline.window_update_fn = h2_window_fn

    return h2_write_fn
end
```

**Why this works without `Ref{Any}`:**
- Write chain: `socket_write!` is a method → `tls_write_fn` captures `tls_state` → `h2_write_fn` captures `tls_write_fn`
- Read chain: `app_read_handler` exists → `h2_read_fn` captures it (plus `tls_write_fn` for cross-dir) → `tls_read_fn` captures `h2_read_fn`
- `socket.read_fn = tls_read_fn` closes the loop — no closure needs to reference anything not yet created

Every closure captures only concrete values. No `Ref{Any}` needed.

### Backpressure

The current system (`channel.jl:1325-1377`) uses per-slot `window_size` with batched
deferred updates via `_channel_window_update_task`. The new system preserves this
layered behavior.

#### Per-Layer Window Tracking

Each middleware layer that translates window sizes maintains its own window state:

- **TLS:** `tls_state.window_size` — tracks ciphertext window (plaintext + record overhead)
- **H2:** `h2_conn.window_size_self` — H2 connection-level flow control window
- **Socket:** `socket.downstream_window` — how much the socket is allowed to read

#### Batched Deferred Updates

The current system batches window updates and schedules a task to propagate them
(avoiding recursive/synchronous cascade under load). The new system preserves this:

```julia
function pipeline_increment_read_window!(pipeline::PipelineState, size::Csize_t)
    if !pipeline.read_back_pressure_enabled || pipeline.state == PipelineLifecycle.SHUT_DOWN
        return nothing
    end

    pipeline.window_update_batch = add_size_saturating(pipeline.window_update_batch, size)

    # Threshold-gated scheduling: only schedule update task when downstream window
    # has dropped below threshold, matching current behavior at channel.jl:1335
    if !pipeline.window_update_scheduled &&
            pipeline.downstream_window <= pipeline.window_update_batch_emit_threshold
        pipeline.window_update_scheduled = true
        event_loop_schedule_task_now!(pipeline.event_loop, pipeline.window_update_task)
    end
end

function _pipeline_window_update_task(pipeline::PipelineState)
    pipeline.window_update_scheduled = false
    pipeline.state == PipelineLifecycle.SHUT_DOWN && return nothing

    batch = pipeline.window_update_batch
    pipeline.window_update_batch = Csize_t(0)

    # Call the window update closure chain (H2 → TLS → socket)
    try
        pipeline.window_update_fn(batch)
    catch e
        e isa ReseauError || rethrow()
        pipeline_shutdown!(pipeline, e.code)
    end
end
```

This matches the current `_channel_window_update_task` behavior: updates are
accumulated in a batch, then a single scheduled task propagates them through
the chain. Each layer applies its translation (TLS adds overhead, H2 manages
its own flow control) and passes the adjusted size upstream.

### Shutdown

Shutdown is bidirectional and ordered, matching the current system exactly.

#### ShutdownChain

```julia
mutable struct ShutdownChain
    # Read shutdown: socket → TLS → H2 → app (left to right)
    # Each fn signature: (error_code::Int, free_scarce::Bool, on_complete::Function) -> Nothing
    # on_complete signature: (error_code::Int, free_scarce::Bool) -> Nothing
    # on_complete is called when this layer's shutdown finishes (may be async)
    read_shutdown_fns::Vector{Any}  # concretely-typed closures stored as Any

    # Write shutdown: app → H2 → TLS → socket (right to left)
    write_shutdown_fns::Vector{Any}

    # Progress tracking
    current_read_idx::Int   # next read shutdown fn to call (starts at 1)
    current_write_idx::Int  # next write shutdown fn to call (starts at 1)
end
```

**Idempotency:** `pipeline_shutdown!` is guarded by `pipeline.state` — it only
proceeds if state is `ACTIVE` and `shutdown_pending` is false. The lock in
`pipeline_shutdown!` ensures concurrent calls are serialized. Once shutdown starts,
subsequent calls are no-ops. This matches current `channel_shutdown!` behavior at
`channel.jl:1526-1533`.

**Error precedence:** The first non-zero error code wins (stored in
`pipeline.shutdown_error_code`). Subsequent layers may report errors via their
`on_complete` callback, but these only overwrite if `shutdown_error_code == 0`.
This matches current `channel_slot_on_handler_shutdown_complete!` at `channel.jl:1590-1592`.

**Mixed sync/async:** Shutdown closures may complete synchronously (call `on_complete`
before returning) or asynchronously (store `on_complete` and call later from a
scheduled task or callback). The cascade logic handles both uniformly — `on_complete`
always advances to the next layer regardless of when it's called. The only constraint
is `on_complete` must be called exactly once per layer. This matches the current
system where `channel_slot_on_handler_shutdown_complete!` is called once per slot.

#### Shutdown Cascade

Matches current `_channel_shutdown_task` → `channel_slot_shutdown!` →
`channel_slot_on_handler_shutdown_complete!` flow:

```julia
function pipeline_shutdown!(pipeline::PipelineState, error_code::Int = 0; immediately::Bool = false)
    schedule_task = false
    lock(pipeline.shutdown_lock) do
        if pipeline.state != PipelineLifecycle.ACTIVE || pipeline.shutdown_pending
            return nothing
        end
        pipeline.shutdown_error_code = error_code
        pipeline.shutdown_immediately = immediately
        pipeline.shutdown_pending = true
        schedule_task = true
    end
    schedule_task || return nothing

    # Schedule shutdown on event loop (matches current channel_shutdown!)
    pipeline_schedule_task_now!(pipeline, pipeline.shutdown_task)
end

function _pipeline_shutdown_task(pipeline::PipelineState)
    if pipeline.state != PipelineLifecycle.ACTIVE
        return nothing
    end

    pipeline.state = PipelineLifecycle.SHUTTING_DOWN_READ
    _shutdown_next_read(pipeline, pipeline.shutdown_error_code, pipeline.shutdown_immediately)
end

function _shutdown_next_read(pipeline, error_code, free_scarce)
    chain = pipeline.shutdown_chain
    idx = chain.current_read_idx
    chain.current_read_idx += 1

    if idx > length(chain.read_shutdown_fns)
        # All read shutdowns complete → transition to write shutdown
        pipeline.state = PipelineLifecycle.SHUTTING_DOWN_WRITE
        # Schedule write shutdown on next event loop tick (matches current behavior)
        task = ScheduledTask(TaskFn(s -> _shutdown_next_write(pipeline, error_code, free_scarce)))
        event_loop_schedule_task_now!(pipeline.event_loop, task)
        return nothing
    end

    on_complete = (err, scarce) -> begin
        # Update error code if non-zero (matches current behavior)
        if err != 0 && pipeline.shutdown_error_code == 0
            pipeline.shutdown_error_code = err
        end
        _shutdown_next_read(pipeline, err, scarce)
    end

    chain.read_shutdown_fns[idx](error_code, free_scarce, on_complete)
end

function _shutdown_next_write(pipeline, error_code, free_scarce)
    chain = pipeline.shutdown_chain
    idx = chain.current_write_idx
    chain.current_write_idx += 1

    if idx > length(chain.write_shutdown_fns)
        # All write shutdowns complete
        pipeline.state = PipelineLifecycle.SHUT_DOWN
        _pipeline_schedule_shutdown_completion!(pipeline)
        return nothing
    end

    on_complete = (err, scarce) -> begin
        if err != 0 && pipeline.shutdown_error_code == 0
            pipeline.shutdown_error_code = err
        end
        _shutdown_next_write(pipeline, err, scarce)
    end

    chain.write_shutdown_fns[idx](error_code, free_scarce, on_complete)
end
```

#### Shutdown Completion (matches `_channel_shutdown_completion_task`)

```julia
function _pipeline_schedule_shutdown_completion!(pipeline::PipelineState)
    task = ScheduledTask(TaskFn(s -> _pipeline_shutdown_completion_task(pipeline)))
    event_loop_schedule_task_now!(pipeline.event_loop, task)
end

function _pipeline_shutdown_completion_task(pipeline::PipelineState)
    # Cancel all pending tasks (matches current behavior)
    tasks = ScheduledTask[]
    lock(pipeline.pending_tasks_lock) do
        for (task, _) in pipeline.pending_tasks
            push!(tasks, task)
        end
    end
    for task in tasks
        event_loop_cancel_task!(pipeline.event_loop, task)
    end

    # Notify shutdown callback
    if pipeline.on_shutdown_completed !== nothing
        pipeline.on_shutdown_completed(pipeline.shutdown_error_code)
    end
end
```

#### Per-Layer Shutdown Closures

Each layer registers its shutdown behavior. Socket and TLS are async; others are sync.

**Socket shutdown** (matches `socket_channel_handler.jl:170-260`):

```julia
function make_socket_shutdown_fns(socket::Socket, pipeline::PipelineState)
    read_shutdown = (error_code, free_scarce, on_complete) -> begin
        socket.shutdown_in_progress = true
        if free_scarce || !socket.is_open
            on_complete(error_code, free_scarce)
        else
            # Async close: subscribe to close event, call on_complete when done
            _socket_close_async(socket, (err) -> on_complete(err, free_scarce))
        end
    end

    write_shutdown = (error_code, free_scarce, on_complete) -> begin
        # Socket write shutdown is immediate — just stop accepting writes
        on_complete(error_code, free_scarce)
    end

    return read_shutdown, write_shutdown
end
```

**TLS shutdown** (matches `s2n_tls_handler.jl:854-890`):

```julia
function make_tls_shutdown_fns(tls_state::S2nTlsState, pipeline::PipelineState)
    read_shutdown = (error_code, free_scarce, on_complete) -> begin
        if free_scarce
            # Immediate shutdown, drain input queue
            _tls_drain_input_queue(tls_state, pipeline)
            tls_state.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
            on_complete(error_code, free_scarce)
        else
            # Delayed shutdown: wait for pending reads to drain
            _tls_delayed_read_shutdown(tls_state, pipeline, error_code, on_complete)
        end
    end

    write_shutdown = (error_code, free_scarce, on_complete) -> begin
        if !free_scarce && error_code != ERROR_IO_SOCKET_CLOSED
            # Send TLS close_notify, then complete
            _tls_delayed_write_shutdown(tls_state, pipeline, error_code, on_complete)
        else
            on_complete(error_code, free_scarce)
        end
    end

    return read_shutdown, write_shutdown
end
```

### Message Lifecycle

Detailed ownership transitions at each boundary to prevent leaks/double-release:

#### Read Path
1. **Socket acquires** from `pipeline.message_pool`
2. Socket dispatches to `read_fn` — **ownership transfers to middleware chain**
3. TLS decrypts: may consume message (partial record → queue), may produce new message(s)
   - If partial: original message queued in `tls_state.input_queue`, TLS acquires new message for decrypted output
   - If error: TLS releases message to pool
4. H2 decodes frames from message, then **releases message to pool**
   - H2 may acquire new messages for cross-direction writes (WINDOW_UPDATE)
   - Per-stream data is dispatched to app via `downstream_read`
5. App receives decoded data, eventually **releases to pool** via `pipeline_increment_read_window!`

#### Write Path
1. **App acquires** from `pipeline.message_pool`
2. App calls `write_fn(msg)` — **ownership transfers to middleware chain**
3. H2 frames the data, may buffer, eventually calls `tls_write_fn`
4. TLS encrypts, calls `socket_write!`
5. Socket writes to OS, registers completion callback
6. **Completion callback releases** message to pool (matches `_on_socket_write_complete`)
7. If write error: completion callback releases message AND triggers shutdown

#### Cross-Direction Write Path (H2 → TLS → Socket during reads)
1. H2 **acquires** message from `pipeline.message_pool` for outgoing frames
2. H2 calls `tls_write_fn(msg)` — ownership transfers to TLS
3. TLS encrypts, calls `socket_write!`
4. Socket completion callback **releases** message to pool

#### Error Path
- Every `try` block around dispatch/write has a `catch` that **releases** the message
- Shutdown drains all queues (TLS input_queue) and releases buffered messages
- This matches the error-path releases in current code:
  - `socket_channel_handler.jl:136-143` (write completion)
  - `s2n_tls_handler.jl:375-376` (send callback failure)
  - `s2n_tls_handler.jl:754` (recv failure)
  - `s2n_tls_handler.jl:882-887` (shutdown drain)

### Protocol Transitions

Three protocol transition scenarios exist. All use the same mechanism: reconstruct
the affected portion of the closure chain and reassign `socket.read_fn` + `socket.write_fn`.

#### 1. ALPN (TLS negotiation selects H1 vs H2)

Handled naturally. TLS negotiation completes before application data flows.
The bootstrap `on_negotiation` callback builds the appropriate protocol middleware:

```julia
function _on_tls_negotiated(tls_state, socket, pipeline, on_protocol_negotiated)
    protocol = _tls_get_negotiated_protocol(tls_state)

    # Ask the app which handler to install (matches current on_protocol_negotiated callback)
    app_read, app_write = on_protocol_negotiated(protocol, socket, pipeline)

    # Build the read chain with the protocol middleware
    tls_read_fn = let tls=tls_state, dr=app_read
        (msg::IoMessage) -> _tls_on_data_received(tls, msg, dr)
    end

    socket.read_fn = tls_read_fn
    socket.write_fn = app_write
end
```

**"Protocol already known" path** (matches `_install_protocol_handler_from_socket`
at `channel_bootstrap.jl:143-157`): When the protocol is already known (e.g.,
reconnecting with cached ALPN), skip negotiation callback and build the pipeline
directly with the known protocol.

#### 2. h2c Upgrade

Same mechanism. H1 handler detects 101 Switching Protocols, triggers pipeline
reconstruction:

```julia
function _h1_on_upgrade_to_h2(h1_conn, socket, pipeline, tls_write_fn, app_handlers)
    h2_conn = H2Connection(...)
    h2_read, h2_write = make_h2_middleware(h2_conn, tls_write_fn, app_handlers.on_stream, pipeline)

    # Reconstruct TLS read to point to H2 instead of H1
    tls_read_fn = let tls=h1_conn.tls_state, dr=h2_read
        (msg::IoMessage) -> _tls_on_data_received(tls, msg, dr)
    end

    socket.read_fn = tls_read_fn
    socket.write_fn = h2_write  # app now writes via H2
end
```

**App write function update:** The app holds a reference to `h1_write_fn` which is
now stale. Solution: the app doesn't hold the write function directly. Instead,
the app calls `socket.write_fn(msg)` (via a function barrier). Since `socket.write_fn`
is reassigned during upgrade, the app always dispatches through the current pipeline.

#### 3. Runtime TLS Upgrade (`tlsupgrade!`)

Matches current `tcp.jl:628-691`. Inserts TLS between socket and app handler:

```julia
function tlsupgrade!(socket::Socket, tls_options::TlsConnectionOptions, pipeline::PipelineState)
    tls_state = S2nTlsState(tls_options, socket, pipeline)

    # Current read_fn is the app handler (plaintext pipeline: socket → app)
    app_read = socket.read_fn
    app_write = socket.write_fn

    # Build TLS middleware
    tls_write_fn = let tls=tls_state
        (msg::IoMessage) -> _tls_encrypt_and_write(tls, msg)
    end
    tls_read_fn = let tls=tls_state, dr=app_read
        (msg::IoMessage) -> _tls_on_data_received(tls, msg, dr)
    end

    socket.read_fn = tls_read_fn
    socket.write_fn = tls_write_fn  # app writes now go through TLS

    # Start TLS negotiation
    _tls_start_negotiation(tls_state)
end
```

### Transition Serialization Contract

**Invariant:** `socket.read_fn` and `socket.write_fn` are ONLY mutated on the event
loop thread. All reads of these fields also happen on the event loop thread (read loop,
write dispatch). This eliminates data races without locks.

**Why this is already guaranteed:**
- Socket readable events fire on the event loop thread → reads always on event loop
- All three transition scenarios (ALPN, h2c, tlsupgrade!) execute on the event loop:
  - ALPN: `on_negotiation` callback runs on event loop (fired from s2n negotiation task)
  - h2c: `_h1_on_upgrade_to_h2` runs during read processing → event loop thread
  - `tlsupgrade!`: current code (`tcp.jl:673-685`) schedules a ChannelTask if not on
    event loop thread, so the actual mutation happens on event loop
- App writes: if called from a non-event-loop thread, the write must be serialized
  through a scheduled task (same as current `TCPSocket` write path at `tcp.jl:920-936`).
  This means the app never directly touches `socket.write_fn` from off-thread —
  it schedules a task that reads `write_fn` on the event loop thread.

**Rule for downstream packages:** Never cache `socket.read_fn` or `socket.write_fn`
in a local variable across an await/yield boundary. Always dispatch through the
socket field. This is enforced by design: the public write API is
`pipeline_write!(socket, msg)` which reads `socket.write_fn` each time.

```julia
function pipeline_write!(socket::Socket, msg::IoMessage)
    if pipeline_thread_is_callers_thread(socket.pipeline)
        _socket_dispatch_write(socket, msg)
    else
        # Schedule write on event loop thread
        task = ScheduledTask(TaskFn(s -> begin
            _socket_dispatch_write(socket, msg)
            return nothing
        end))
        pipeline_schedule_task_now!(socket.pipeline, task)
    end
end

@inline function _socket_dispatch_write(socket::Socket, msg::IoMessage)
    (socket.write_fn::Function)(msg)
    return nothing
end
```

**Stale closure risk eliminated:** The app never holds a write closure directly.
The app calls `pipeline_write!(socket, msg)` which always reads the current
`socket.write_fn`. Even if an upgrade happens between two writes, the second
write will see the new pipeline. Any in-flight scheduled write tasks read
`socket.write_fn` at execution time (on event loop), not at scheduling time.

**Cross-protocol write invariant:** Transitions must drain in-flight writes before
swapping `write_fn`. In practice this is already guaranteed for all three scenarios:

- **ALPN:** No application data flows before TLS negotiation completes. The write
  chain is only set after protocol selection, so no in-flight writes exist.
- **h2c upgrade:** The H1 handler processes the 101 response during a read callback
  on the event loop. At that point, the event loop is occupied — no scheduled write
  tasks can execute during the swap. Any previously scheduled writes will have already
  executed (event loop tasks are FIFO). After the swap, new writes go through H2.
- **`tlsupgrade!`:** The caller blocks (via `wait(negotiation_event)`) until TLS
  negotiation completes. No application writes are issued during the upgrade window.
  If writes were scheduled before `tlsupgrade!`, they execute on the event loop
  before the upgrade task runs (FIFO ordering).

If future transition scenarios break this invariant, add an explicit drain:
```julia
function _drain_pending_writes_before_transition!(pipeline::PipelineState)
    # Flush all pending cross-thread tasks (which may include writes)
    _pipeline_flush_cross_thread_tasks!(pipeline)
end
```

### Event Loop Integration

No change to the event loop itself. Key integration points preserved:

- **Readable events:** Event loop → `_socket_on_readable(socket)` → read loop
- **Task scheduling:** Closures capture `pipeline` for scheduling deferred work
- **Cross-thread tasks:** `PipelineState` handles cross-thread dispatch identically to current `Channel`:
  - `pipeline_schedule_task_now!` checks thread, queues if not on event loop thread
  - `_pipeline_schedule_cross_thread_tasks` drains queue on event loop thread
  - Tasks tracked in `pending_tasks`, canceled on shutdown
- **Thread checks:** `pipeline_thread_is_callers_thread(pipeline)` — same semantics as `channel_thread_is_callers_thread`

### Extensibility

Two extension points for downstream packages (like AwsHTTP):

**1. Custom middleware:** Any package defines a `make_X_middleware(...)` function
returning `(read_fn, write_fn)` closures plus optional `(window_fn, read_shutdown, write_shutdown)`.

**2. Custom app handler:** The terminal `app_read` closure is provided by the
application. It receives decrypted, deframed messages.

**3. Custom bootstrap:** Downstream packages provide their own `build_X_pipeline`
functions that compose middleware as needed. The only contract is:
- Set `socket.read_fn` and `socket.write_fn`
- Populate `pipeline.shutdown_chain`
- Provide `pipeline.window_update_fn`

### What's Eliminated

| Current | New | Notes |
|---------|-----|-------|
| `AbstractChannelHandler` | eliminated | No abstract handler type |
| `ChannelSlot` (7 callable fields) | eliminated | Closures replace dispatch |
| `ChannelHandlerReadCallable` etc. (6 wrapper types) | eliminated | Direct closure calls |
| `_ChannelHandlerReadDispatch` etc. (6 dispatch structs) | eliminated | Closures are the dispatch |
| `adj_left` / `adj_right` linked list | eliminated | Closures capture their targets |
| `AlpnHandler` | eliminated | Folded into bootstrap |
| `channel_slot_send_message` | eliminated | Direct closure calls |
| `channel_slot_replace!` | eliminated | One-time construction |
| `Socket.handler` field (abstract type) | eliminated | Socket is self-contained |
| `TCPSocket.handler` field (abstract type) | eliminated | Not needed |

### What's Kept (Largely Unchanged)

- `PipelineState` ≈ `Channel` (minus slot management, plus shutdown chain)
- `MessagePool` — same
- `EventLoop` — same
- `IoMessage` — same
- `S2nTlsState` ≈ `S2nTlsHandler` (minus slot/channel refs, plus socket ref)
- `SecureTransportTlsState` ≈ `SecureTransportTlsHandler` (same treatment)
- `H2Connection` — internal logic unchanged
- `H1Connection` — internal logic unchanged
- `Socket` struct — merged with SocketChannelHandler
- Bootstrap flow — same shape, different wiring

### Testing Strategy

- **State structs are directly testable:** S2nTlsState, H2Connection, H1Connection
  contain all the logic. Tests create mock closures (simple lambda recording calls)
  and pass them as downstream/upstream refs.
- **Integration tests:** Build real pipelines with mock sockets (pre-loaded byte
  buffers instead of OS fds) and verify end-to-end message flow.
- **Shutdown tests:** Verify shutdown cascade ordering by recording callback invocation
  order in mock shutdown closures.
- **Backpressure tests:** Verify window translations by checking socket.downstream_window
  after app calls pipeline_increment_read_window!.

### Migration Path

1. Create `PipelineState` as a slim `Channel` replacement with cross-thread task support.
2. Create `ShutdownChain` and shutdown cascade logic.
3. Merge `SocketChannelHandler` into `Socket`, implement function barriers.
4. Convert `S2nTlsHandler` → `S2nTlsState` + `make_tls_middleware` + `make_tls_shutdown_fns`.
5. Convert `SecureTransportTlsHandler` → same treatment.
6. Convert `H1Connection` handler interface → `make_h1_middleware`.
7. Convert `H2Connection` handler interface → `make_h2_middleware`.
8. Build backpressure closure chain in pipeline constructors.
9. Update bootstrap to use two-pass construction.
10. Update `tlsupgrade!` on TCPSocket.
11. Remove `ChannelSlot`, `AbstractChannelHandler`, all callable/dispatch wrappers.
12. Update AwsHTTP to use new middleware factories.
13. Update tests.

### Resolved Design Decisions

1. **`socket.read_fn::Any` trim-safety strategy** (mandatory, not optional):
   - **Phase 1:** Implement with `::Any` + function barrier. Test with `--trim=safe`.
   - **Phase 2 (if Phase 1 fails trim):** Add explicit `precompile` directives for
     all closure types. The universe of closures that can appear in `read_fn`/`write_fn`
     is bounded and enumerable:
     - `tls_read_fn` (captures S2nTlsState + downstream)
     - `h1_read_fn` / `h1_write_fn` (captures H1Connection + deps)
     - `h2_read_fn` / `h2_write_fn` (captures H2Connection + deps)
     - `app_read` (provided by downstream package — finite set per package)
     - Direct app handler for plaintext (captures app state)
   - **Phase 3 (if Phase 2 fails trim):** Replace `::Any` with `FunctionRef` that
     stores a cfunction pointer alongside the closure, using the same pattern as
     the current `ChannelHandlerReadCallable` but without `Ptr{Cvoid}` type erasure.
   - This is the only dynamic dispatch point in the entire pipeline. The current
     system has ~7 per slot (read, write, window, shutdown, overhead, destroy, trigger).

2. **Backpressure**: Layered closure chain with per-layer window tracking + batched
   deferred updates on PipelineState with threshold gating. Preserves current
   semantics including `window_update_batch_emit_threshold` behavior.

3. **Shutdown**: Explicit phase state machine on PipelineState + closure chain with
   async `on_complete` callbacks. Event-loop-scheduled transitions between phases.
   Pending task cancellation on completion.

4. **Protocol transitions**: All mutations of `socket.read_fn`/`socket.write_fn`
   happen exclusively on the event loop thread. App writes go through
   `pipeline_write!(socket, msg)` which reads the current `write_fn` each time.
   No stale closure risk.

5. **Message lifecycle**: Explicit ownership transfer rules at each boundary.
   Error paths always release. Shutdown drains queues.

6. **Testing**: State structs are testable in isolation with mock closures.
   Integration tests verify wiring.

7. **Transition serialization**: Event-loop-only mutation of dispatch fields.
   Public API (`pipeline_write!`) serializes off-thread writes via scheduled tasks.
   Downstream packages must never cache dispatch closures across yield points.

### Implementation Risks (Watch List)

These are not design gaps but areas that need careful attention during implementation:

1. **Trim validation gate:** Run `--trim=safe` after Phase 1 implementation. If
   `::Any` dispatch fails trim, move immediately to Phase 2 (precompile) or Phase 3
   (FunctionRef). Do not defer.

2. **Cross-protocol write invariant testing:** Add explicit tests for off-thread
   `pipeline_write!` scheduling around each transition (ALPN, h2c, tlsupgrade!).
   Verify no in-flight write uses a stale pipeline. If FIFO scheduling assumptions
   prove fragile, add explicit `_drain_pending_writes_before_transition!` calls.

3. **Shutdown idempotency vs late errors:** Verify that suppressing later non-zero
   error codes once shutdown is pending matches legacy semantics exactly. The current
   code (`channel.jl:1590-1592`) only overwrites if `shutdown_error_code == 0` —
   match this behavior precisely.

4. **ShutdownChain single-use:** `current_read_idx`/`current_write_idx` are one-shot
   cursors. Verify no code path reuses a PipelineState after shutdown (e.g., connection
   pool recycling). If reuse is needed, reset the chain indices.

5. **Migration scope:** This requires coordinated changes across channel.jl, socket.jl,
   tcp.jl, bootstrap, TLS handlers, and AwsHTTP. Partial migration will leave
   inconsistent threading/ownership guarantees. Plan for atomic switchover per
   pipeline configuration (plaintext first, then TLS, then TLS+H2).

6. **Concurrency testing:** Off-thread `pipeline_write!` around transitions is the
   highest-risk concurrency scenario. Build targeted tests early.
