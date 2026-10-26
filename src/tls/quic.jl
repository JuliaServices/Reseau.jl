# TLS for QUIC (RFC 9001), ported from Go's `crypto/tls/quic.go`.
#
# A `QUICConn` runs the same TLS 1.3 handshake state machines as `Conn`, with
# itself as the handshake io: handshake messages travel in QUIC CRYPTO frames
# instead of TLS records, and traffic secrets go to the QUIC layer instead of a
# record cipher. Go runs the blocking handshake in a goroutine and hands control
# back and forth over channels. Here a `Task` runs it, and `cond` passes the
# turn so exactly one side runs at a time: the caller while the handshake is
# blocked on data or transport parameters, the handshake otherwise.

"""
    QUICEncryptionLevel

QUIC encryption level used to transmit handshake messages (RFC 9001 Section
4.1.4). Values: `Initial`, `Early`, `Handshake`, `Application`.
"""
module QUICEncryptionLevel
Base.@enum T::UInt8 begin
    Initial = 0
    Early = 1
    Handshake = 2
    Application = 3
end
end

"""
    QUICEventKind

Kind of a [`QUICEvent`](@ref Reseau.TLS.QUICEvent):

- `NoEvent`: no events are pending.
- `SetReadSecret`, `SetWriteSecret`: `level`, `suite`, and `data` (the traffic
  secret) are set. Initial secrets come from the destination connection ID and
  are never produced here.
- `WriteData`: `level` and `data` are set; send `data` in CRYPTO frames.
- `TransportParameters`: `data` holds the peer's QUIC transport parameters.
- `TransportParametersRequired`: call [`set_transport_parameters!`](@ref Reseau.TLS.set_transport_parameters!), then
  keep reading events.
- `HandshakeDone`: the TLS handshake completed.
- `Error`: the handshake failed; `err` is set and the connection must close.
"""
module QUICEventKind
Base.@enum T::UInt8 begin
    NoEvent = 0
    SetReadSecret = 1
    SetWriteSecret = 2
    WriteData = 3
    TransportParameters = 4
    TransportParametersRequired = 5
    HandshakeDone = 6
    Error = 7
end
end

"""
    QUICEvent

One step of a QUIC TLS handshake, returned by [`next_event!`](@ref). Which
fields are meaningful depends on `kind` (see [`QUICEventKind`](@ref)). The
event owns `data`.
"""
struct QUICEvent
    kind::QUICEventKind.T
    level::QUICEncryptionLevel.T
    data::Vector{UInt8}
    suite::UInt16
    err::Union{Nothing, TLSError}
end

# The `data` of events that carry none, shared so that polling for events
# does not allocate; never mutated.
const _QUIC_NO_DATA = UInt8[]

@inline function _quic_event(
        kind::QUICEventKind.T;
        level::QUICEncryptionLevel.T = QUICEncryptionLevel.Initial,
        data::Vector{UInt8} = _QUIC_NO_DATA,
        suite::UInt16 = UInt16(0),
        err::Union{Nothing, TLSError} = nothing,
    )::QUICEvent
    return QUICEvent(kind, level, data, suite, err)
end

"""
    QUICConn

TLS 1.3 handshake for a QUIC connection (RFC 9001), created by
[`quic_client`](@ref) or [`quic_server`](@ref). It carries no application data:
the QUIC implementation feeds it CRYPTO-frame bytes with
[`handle_data!`](@ref) and acts on what [`next_event!`](@ref) returns.

Methods of `QUICConn` are not safe for concurrent use.
"""
mutable struct QUICConn
    config::Config
    is_server::Bool
    cond::Threads.Condition
    # True while the handshake task holds the turn; guarded by `cond`.
    handshake_turn::Bool
    started::Bool
    handshake_exited::Bool
    closed::Bool
    handshake_complete::Bool
    session_ticket_sent::Bool
    read_level::QUICEncryptionLevel.T
    write_level::QUICEncryptionLevel.T
    hand::Vector{UInt8}
    hand_pos::Int
    events::Vector{QUICEvent}
    next_event::Int
    transport_parameters::Union{Nothing, Vector{UInt8}}
    handshake_error::Union{Nothing, TLSError}
    error_returned::Bool
    negotiated_alpn::Union{Nothing, String}
    # Resumption material and negotiated metadata, as for `Conn`; the record
    # fields stay unused.
    native_state::_TLS13NativeClientState
end

function _new_quic_conn(config::Config, is_server::Bool)::QUICConn
    _validate_config(config; is_server)
    # QUIC ignores min_version: it only ever speaks TLS 1.3 (RFC 9001 Section 4.2).
    _config_allows_tls_version(config, TLS1_3_VERSION) || throw(ConfigError("QUIC requires TLS 1.3"))
    return QUICConn(
        config,
        is_server,
        Threads.Condition(),
        false,
        false,
        false,
        false,
        false,
        false,
        QUICEncryptionLevel.Initial,
        QUICEncryptionLevel.Initial,
        UInt8[],
        1,
        QUICEvent[],
        1,
        nothing,
        nothing,
        false,
        nothing,
        _TLS13NativeClientState(),
    )
end

"""
    quic_client(config::Config) -> QUICConn

Create the client side of a QUIC TLS handshake. QUIC always negotiates TLS 1.3,
so `config` must allow it; `handshake_timeout_ns` is ignored because the QUIC
layer owns timeouts. Sessions are cached under `config.server_name`, so
resumption needs it set.
"""
quic_client(config::Config)::QUICConn = _new_quic_conn(config, false)

"""
    quic_server(config::Config) -> QUICConn

Create the server side of a QUIC TLS handshake. `config` needs `cert_file` and
`key_file` and must allow TLS 1.3. Session tickets are only issued through
[`send_session_ticket!`](@ref).
"""
quic_server(config::Config)::QUICConn = _new_quic_conn(config, true)

"""
    alert_code(err::TLSError) -> UInt8

TLS alert description behind `err`, or `internal_error` (80) when the failure
did not come from a TLS alert. QUIC reports a handshake failure as
CRYPTO_ERROR `0x0100 + alert_code(err)` (RFC 9001 Section 4.8).
"""
function alert_code(err::TLSError)::UInt8
    cause = err.cause
    cause isa _TLSAlertError && return (cause::_TLSAlertError).alert
    return _TLS_ALERT_INTERNAL_ERROR
end

# `@nospecialize` keeps calls from `catch` blocks static under `juliac --trim`,
# as for `_throw_tls_read_error`.
function _quic_error(op::String, @nospecialize(ex::Exception))::TLSError
    ex isa TLSError && return ex::TLSError
    ex isa _TLSAlertError && return TLSError(op, Int32(0), (ex::_TLSAlertError).message, ex)
    ex isa ArgumentError && return TLSError(op, Int32(0), _quic_message((ex::ArgumentError).msg), ex)
    return TLSError(op, Int32(0), "unexpected TLS failure", ex)
end

# An ArgumentError's message is any AbstractString.
function _quic_message(@nospecialize(msg))::String
    msg isa String && return msg::String
    msg isa SubString{String} && return String(msg::SubString{String})
    return "invalid argument"
end

@inline _quic_misuse_error(op::String, message::String)::TLSError = TLSError(op, Int32(0), message, nothing)

"""
    start!(q::QUICConn)

Start the handshake. The client queues its ClientHello; read the resulting
events with [`next_event!`](@ref). Call at most once. Throws `TLSError` if the
handshake has already failed.
"""
function start!(q::QUICConn)::Nothing
    q.closed && throw(_closed_error("start"))
    q.started && throw(_quic_misuse_error("start", "tls: start! called more than once"))
    q.started = true
    task = Task(() -> _quic_run_handshake!(q))
    # A sticky task would pin the task scheduling it to its thread.
    task.sticky = false
    lock(q.cond)
    try
        q.handshake_turn = true
        schedule(task)
        while q.handshake_turn
            wait(q.cond)
        end
    finally
        unlock(q.cond)
    end
    err = q.handshake_error
    err === nothing || throw(err)
    return nothing
end

"""
    next_event!(q::QUICConn) -> QUICEvent

Return the next pending event, or one with kind `NoEvent` when there is none.
After a failure the `Error` event comes once, ahead of anything still queued.
"""
function next_event!(q::QUICConn)::QUICEvent
    err = q.handshake_error
    if err !== nothing
        q.error_returned && return _quic_event(QUICEventKind.NoEvent)
        q.error_returned = true
        empty!(q.events)
        q.next_event = 1
        return _quic_event(QUICEventKind.Error; err)
    end
    if q.next_event > length(q.events)
        empty!(q.events)
        q.next_event = 1
        return _quic_event(QUICEventKind.NoEvent)
    end
    event = q.events[q.next_event]
    q.next_event += 1
    return event
end

"""
    handle_data!(q::QUICConn, level::QUICEncryptionLevel.T, data)

Feed handshake bytes received from the peer in CRYPTO frames at `level`, in
order. Bytes may arrive split at any point. Throws `TLSError` if the data is at
the wrong level or the handshake fails; after the handshake the only message
accepted is a client receiving NewSessionTicket.
"""
function handle_data!(q::QUICConn, level::QUICEncryptionLevel.T, data::AbstractVector{UInt8})::Nothing
    q.closed && throw(_closed_error("handle_data"))
    q.started || throw(_quic_misuse_error("handle_data", "tls: handle_data! called before start!"))
    level == q.read_level ||
        throw(_quic_misuse_error("handle_data", "tls: handshake data received at wrong level"))
    append!(q.hand, data)
    q.handshake_exited || _quic_resume_handshake!(q)
    err = q.handshake_error
    err === nothing || throw(err)
    # Bytes the handshake left unread, and anything after it, are post-handshake.
    q.handshake_exited && _quic_handle_post_handshake_messages!(q)
    return nothing
end

"""
    set_transport_parameters!(q::QUICConn, params)

Set the QUIC transport parameters to send to the peer. Set them before
[`start!`](@ref), or when a `TransportParametersRequired` event asks; a server
may wait until it has seen the client's.
"""
function set_transport_parameters!(q::QUICConn, params::AbstractVector{UInt8})::Nothing
    q.transport_parameters = Vector{UInt8}(params)
    q.started && !q.handshake_exited && !q.closed && _quic_resume_handshake!(q)
    return nothing
end

"""
    send_session_ticket!(q::QUICConn)

Queue a NewSessionTicket for the client as a `WriteData` event at the
`Application` level. Server only, once, after `HandshakeDone`. Does nothing
when `config.session_tickets_disabled` is set or the client cannot resume.
"""
function send_session_ticket!(q::QUICConn)::Nothing
    q.config.session_tickets_disabled && return nothing
    q.closed && throw(_closed_error("send_session_ticket"))
    q.handshake_complete ||
        throw(_quic_misuse_error("send_session_ticket", "tls: send_session_ticket! called before the handshake completed"))
    q.is_server || throw(_quic_misuse_error("send_session_ticket", "tls: send_session_ticket! called on the client"))
    q.session_ticket_sent && throw(_quic_misuse_error("send_session_ticket", "tls: send_session_ticket! called more than once"))
    q.session_ticket_sent = true
    native_state = q.native_state
    # Empty when the client offered no psk_dhe_ke mode (RFC 8446 Section 4.2.9).
    isempty(native_state.resumption_secret) && return nothing
    try
        _tls13_write_new_session_ticket!(
            q,
            q.config,
            native_state.session_cipher_suite,
            native_state.resumption_secret,
            native_state.session_certificates,
            native_state.session_alpn,
        )
    catch ex
        throw(_quic_error("send_session_ticket", _as_exception(ex)))
    finally
        _securezero!(native_state.resumption_secret)
        empty!(native_state.resumption_secret)
    end
    return nothing
end

"""
    connection_state(q::QUICConn) -> ConnectionState

Snapshot of what the handshake has negotiated so far. A server reports its
ALPN choice from the `Handshake` secrets on; a client once it has the server's
Finished.
"""
function connection_state(q::QUICConn)::ConnectionState
    native_state = q.native_state
    complete = q.handshake_complete
    return ConnectionState(
        complete,
        complete ? "TLSv1.3" : "",
        q.negotiated_alpn,
        native_state.session_cipher_suite == UInt16(0) ? nothing : _tls13_cipher_suite_name(native_state.session_cipher_suite),
        true,
        native_state.did_resume,
        native_state.did_hello_retry_request,
        !q.is_server && _tls13_has_resumable_session(q.config, _quic_client_session_cache_key(q.config)),
        native_state.curve_id == UInt16(0) ? nothing : _tls_group_name(native_state.curve_id),
    )
end

"""
    close(q::QUICConn)

Stop any handshake in progress and drop retained secrets. A handshake stopped
this way ends with a `close_notify` error.
"""
function Base.close(q::QUICConn)::Nothing
    q.closed && return nothing
    q.closed = true
    while q.started && !q.handshake_exited
        _quic_resume_handshake!(q)
    end
    native_state = q.native_state
    _securezero!(native_state.resumption_secret)
    empty!(native_state.resumption_secret)
    for cert in native_state.session_certificates
        _securezero!(cert)
    end
    empty!(native_state.session_certificates)
    _securezero!(q.hand)
    empty!(q.hand)
    q.hand_pos = 1
    return nothing
end

@inline _native_tls13_state(q::QUICConn)::_TLS13NativeClientState = q.native_state

# Go's QUIC client has no remote address to fall back on, so only a configured
# server name keys the session cache.
@inline function _quic_client_session_cache_key(config::Config)::String
    server_name = config.server_name
    return server_name === nothing ? "" : server_name::String
end

# Turn handoff. The caller gives the handshake task the turn and waits for it
# back; the task returns it when it blocks (`_quic_wait_for_signal!`) or exits.

function _quic_resume_handshake!(q::QUICConn)::Nothing
    lock(q.cond)
    try
        q.handshake_turn = true
        notify(q.cond)
        while q.handshake_turn
            wait(q.cond)
        end
    finally
        unlock(q.cond)
    end
    return nothing
end

function _quic_wait_for_signal!(q::QUICConn)::Nothing
    lock(q.cond)
    try
        q.handshake_turn = false
        notify(q.cond)
        while !q.handshake_turn
            wait(q.cond)
        end
    finally
        unlock(q.cond)
    end
    # Go ends a canceled handshake with close_notify.
    q.closed && _tls_fail(_TLS_ALERT_CLOSE_NOTIFY, "tls: QUIC connection closed during the handshake")
    return nothing
end

function _quic_run_handshake!(q::QUICConn)::Nothing
    try
        q.is_server ? _quic_server_handshake!(q) : _quic_client_handshake!(q)
    catch ex
        q.handshake_error = _quic_error("handshake", _as_exception(ex))
    finally
        lock(q.cond)
        try
            q.handshake_exited = true
            q.handshake_turn = false
            notify(q.cond)
        finally
            unlock(q.cond)
        end
    end
    return nothing
end

function _quic_client_handshake!(q::QUICConn)::Nothing
    config = q.config
    params = _quic_transport_parameters_to_send!(q)::Vector{UInt8}
    cache_key = _quic_client_session_cache_key(config)
    client_hello = _tls13_client_hello(config)
    # RFC 9001 Section 8.4: no middlebox-compatibility session ID.
    client_hello.session_id = UInt8[]
    client_hello.quic_transport_parameters = params
    session = _tls13_try_load_client_session(config, cache_key, client_hello)
    state = _TLS13ClientHandshakeState(
        client_hello,
        _TLS13OpenSSLKeyShareProvider(),
        _native_tls13_certificate_verifier(config),
        session,
    )
    try
        _client_handshake_tls13!(state, q, config)
        q.negotiated_alpn = _tls13_record_client_session!(q.native_state, config, state, cache_key)
        _quic_handshake_done!(q, state.cipher_suite, state.server_application_traffic_secret)
    finally
        _securezero_tls13_client_handshake_state!(state)
    end
    return nothing
end

function _quic_server_handshake!(q::QUICConn)::Nothing
    config = q.config
    state = _TLS13ServerHandshakeState(config)
    try
        _server_handshake_tls13!(state, q, config)
        q.negotiated_alpn = _tls13_record_server_session!(q.native_state, config, state)
        # Keep only what `send_session_ticket!` needs once the handshake state is zeroed.
        if _tls13_should_send_session_tickets(state, config)
            native_state = q.native_state
            native_state.resumption_secret = _tls13_derive_secret(state.cipher_spec.hash_kind, state.master_secret, "res master", state.transcript)
            native_state.session_certificates = [copy(cert) for cert in state.peer_certificates]
        end
        _quic_handshake_done!(q, state.cipher_suite, state.client_application_traffic_secret)
    finally
        _securezero_tls13_server_handshake_state!(state)
    end
    return nothing
end

function _quic_handshake_done!(q::QUICConn, suite::UInt16, peer_application_secret::Vector{UInt8})::Nothing
    q.handshake_complete = true
    push!(q.events, _quic_event(QUICEventKind.HandshakeDone))
    # RFC 9001 Section 5.7: the QUIC layer must not decrypt 1-RTT packets before
    # the handshake completes, so the 1-RTT read secret comes last.
    push!(q.events, _quic_event(QUICEventKind.SetReadSecret; level = QUICEncryptionLevel.Application, suite, data = copy(peer_application_secret)))
    return nothing
end

function _quic_handle_post_handshake_messages!(q::QUICConn)::Nothing
    try
        while true
            raw = _quic_take_handshake_message!(q)
            raw === nothing && return nothing
            if raw[1] == _TLS13_HANDSHAKE_TYPE_KEY_UPDATE
                # RFC 9001 Section 6: QUIC replaces KeyUpdate with its key phase bit.
                _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected key update message")
            end
            q.is_server && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected post-handshake message from the client")
            msg = _tls13_validate_new_session_ticket(raw)
            msg.lifetime == 0x00000000 && continue
            _tls13_store_new_session_ticket!(q, msg)
        end
    catch ex
        err = _quic_error("handle_data", _as_exception(ex))
        q.handshake_error = err
        throw(err)
    end
end

function _quic_take_handshake_message!(q::QUICConn)::Union{Nothing, Vector{UInt8}}
    raw = _tls_peek_handshake_message(q.hand, q.hand_pos)
    raw === nothing && return nothing
    q.hand_pos = _tls_compact_buffer!(q.hand, q.hand_pos + length(raw))
    return raw
end

function _quic_set_read_level!(q::QUICConn, level::QUICEncryptionLevel.T)::Nothing
    # Bytes buffered under the old keys must not be parsed under the new ones.
    _tls_buffer_available(q.hand, q.hand_pos) == 0 ||
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: handshake buffer not empty before setting read traffic secret")
    q.read_level = level
    return nothing
end

function _quic_set_read_secret!(q::QUICConn, level::QUICEncryptionLevel.T, suite::UInt16, secret::Vector{UInt8})::Nothing
    _quic_set_read_level!(q, level)
    push!(q.events, _quic_event(QUICEventKind.SetReadSecret; level, suite, data = copy(secret)))
    return nothing
end

function _quic_set_write_secret!(q::QUICConn, level::QUICEncryptionLevel.T, suite::UInt16, secret::Vector{UInt8})::Nothing
    q.write_level = level
    push!(q.events, _quic_event(QUICEventKind.SetWriteSecret; level, suite, data = copy(secret)))
    return nothing
end

# Handshake io implementation used by the shared TLS 1.3 state machines.

@inline _tls_is_quic(::QUICConn)::Bool = true

# RFC 9001 Section 8.4: QUIC endpoints never send ChangeCipherSpec.
@inline _tls13_send_dummy_change_cipher_spec!(::QUICConn)::Nothing = nothing

# Post-handshake messages arrive through `handle_data!` after the handshake exits.
@inline _remaining_handshake_messages(::QUICConn)::Int = 0

function _read_handshake_bytes!(q::QUICConn)::Vector{UInt8}
    while true
        raw = _quic_take_handshake_message!(q)
        raw !== nothing && return raw
        _quic_wait_for_signal!(q)
    end
end

function _write_handshake_bytes!(q::QUICConn, raw::Vector{UInt8})::Nothing
    # Extend a still-queued WriteData event at this level, as Go does.
    n = length(q.events)
    if n >= q.next_event
        last = q.events[n]
        if last.kind == QUICEventKind.WriteData && last.level == q.write_level
            append!(last.data, raw)
            return nothing
        end
    end
    push!(q.events, _quic_event(QUICEventKind.WriteData; level = q.write_level, data = copy(raw)))
    return nothing
end

function _quic_set_peer_transport_parameters!(q::QUICConn, params::Vector{UInt8})::Nothing
    push!(q.events, _quic_event(QUICEventKind.TransportParameters; data = copy(params)))
    return nothing
end

function _quic_transport_parameters_to_send!(q::QUICConn)::Union{Nothing, Vector{UInt8}}
    if q.transport_parameters === nothing
        push!(q.events, _quic_event(QUICEventKind.TransportParametersRequired))
        while q.transport_parameters === nothing
            _quic_wait_for_signal!(q)
        end
    end
    return copy(q.transport_parameters::Vector{UInt8})
end

function _tls13_on_handshake_keys!(q::QUICConn, state::_TLS13ClientHandshakeState)::Nothing
    _quic_set_write_secret!(q, QUICEncryptionLevel.Handshake, state.cipher_suite, state.client_handshake_traffic_secret)
    _quic_set_read_secret!(q, QUICEncryptionLevel.Handshake, state.cipher_suite, state.server_handshake_traffic_secret)
    return nothing
end

function _tls13_on_server_finished!(q::QUICConn, state::_TLS13ClientHandshakeState)::Nothing
    # The 1-RTT read secret itself waits for `_quic_handshake_done!`.
    _quic_set_read_level!(q, QUICEncryptionLevel.Application)
    q.negotiated_alpn = _tls13_client_negotiated_alpn(state)
    return nothing
end

function _tls13_on_client_finished!(q::QUICConn, state::_TLS13ClientHandshakeState)::Nothing
    _quic_set_write_secret!(q, QUICEncryptionLevel.Application, state.cipher_suite, state.client_application_traffic_secret)
    return nothing
end

function _tls13_on_handshake_keys!(q::QUICConn, state::_TLS13ServerHandshakeState)::Nothing
    _quic_set_write_secret!(q, QUICEncryptionLevel.Handshake, state.cipher_suite, state.server_handshake_traffic_secret)
    _quic_set_read_secret!(q, QUICEncryptionLevel.Handshake, state.cipher_suite, state.client_handshake_traffic_secret)
    q.negotiated_alpn = _tls13_server_negotiated_alpn(q.config, state)
    return nothing
end

function _tls13_on_server_finished!(q::QUICConn, state::_TLS13ServerHandshakeState)::Nothing
    _quic_set_write_secret!(q, QUICEncryptionLevel.Application, state.cipher_suite, state.server_application_traffic_secret)
    return nothing
end

function _tls13_on_client_finished!(q::QUICConn, ::_TLS13ServerHandshakeState)::Nothing
    # The 1-RTT read secret itself waits for `_quic_handshake_done!`.
    _quic_set_read_level!(q, QUICEncryptionLevel.Application)
    return nothing
end
