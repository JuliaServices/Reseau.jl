# Native Unix domain socket support (design sketch)

Status: sketch, revision 5 (2026-08-24; revised after codex review rounds 1–4
— `unix-sockets-codex-r{1,2,3,4}.md`). Decided: the
`StreamConn` hoist (option B below) and a `Union{TCP.Conn, Unix.Conn}`
transport field in `TLS.Conn` (not a type parameter).

## Goal

Add a stream-oriented local IPC transport — Unix domain sockets — as a peer of
`TCP`, usable anywhere a `TCP.Conn` is usable today (including under `TLS`,
through `SOCKS`, and as a MySQL/Postgres-style local transport):

```julia
conn = Unix.connect("/tmp/mysql.sock")
listener = Unix.listen("/tmp/my-service.sock")
child = Unix.accept(listener)
```

Scope for v1:

- `SOCK_STREAM` only (`unixgram`/`unixpacket` have zero observed demand; the
  stdlib-replacement audit found no UDP-style local IPC consumers either).
- Cross-platform: Linux, macOS, FreeBSD, and Windows 10 1803+ / Server 2019+
  via native `AF_UNIX` (`afunix.sys`).
- Windows *named pipes* (`\\.\pipe\...`) are explicitly **out of scope** for
  v1 — see "Why AF_UNIX on Windows, not named pipes" below.
- The public v1 API is `Unix.connect(path)` / `Unix.listen(path)` only. A
  Go-style two-string `connect("unix", path)` generic is deferred: the
  existing two-string methods live on `TCP.connect`/`TCP.listen`, return
  `TCP.Conn`/`TCP.Listener`, and thread `OpError` endpoints typed as the
  IP-only `SocketEndpoint` union — widening all of that is its own small
  design and buys nothing for the motivating use cases (see Future work).

## What already exists (survey)

The current stack is close to family-agnostic; most of what sits below the
address layer needs no changes:

| Layer | Status for AF_UNIX |
| --- | --- |
| `SocketOps.AF_UNIX` | already defined (`Cint(1)`, correct on all platforms) |
| `open_socket(family, sotype)` | generic on all three backends; Windows passes family straight to `WSASocketW` with `WSA_FLAG_OVERLAPPED` — works for `AF_UNIX` |
| `bind_socket` / `connect_socket` | raw `(Ptr{Cvoid}, SockLen)` overloads exist on all backends — no new syscall wrappers needed (Windows already has a direct nonblocking `connect` wrapper, `socket_ops/windows.jl:664–682`) |
| `IOPoll` (kqueue/epoll) | fd-based readiness; family never inspected — zero changes |
| `IOPoll` (IOCP) — accept + I/O | `accept!` opens the child with the listener's `(family, sotype)`; `AcceptEx`/`WSARecv`/`WSASend` support afunix sockets |
| `IOPoll` (IOCP) — connect | **not usable for AF_UNIX**: `IOPoll.connect!` submits `ConnectEx`, which does not support unix sockets. Both Go (`canUseConnectEx` is TCP-only) and .NET (routes `AddressFamily.Unix` through `WSAConnect`) use ordinary connect here. Windows unix connect needs its own small path — see "Windows connect" below |
| Accept addr buffers | `_ACCEPT_ADDRBUF_LEN = 128` on both POSIX and Windows; `sockaddr_un` is ≤110 bytes and AcceptEx needs `size+16 = 126` per slot — fits |
| `NetCommon.FD` | carries `family`, `sotype`, `net::Symbol`, `laddr/raddr::Union{Nothing,SocketAddr}` — designed for this |
| read/write/eof/deadlines/fdlock/finalizer | all fd-level, family-agnostic; `MSG_PEEK` eof-probe works on unix stream sockets |
| SIGPIPE | Julia initializes with SIGPIPE ignored, so writes surface `EPIPE`, same as TCP (an embedder can change the process-wide disposition; not our problem to solve) |

What is actually missing:

1. `sockaddr_un` structs, builders, and decoders in `SocketOps`.
2. `getsockname`/`getpeername` for the unix family (only `_in`/`_in6` variants
   exist).
3. A `SocketAddrUnix <: SocketAddr` endpoint type — plus narrowing the
   IP-only entry points so the new subtype cannot leak into them (below).
4. A public `Unix` module (connect/listen/accept + listener path lifecycle).
5. The `StreamConn` hoist so `Unix.Conn` shares the `TCP.Conn` IO surface.
6. A Windows connect path that does not go through `ConnectEx`.

## Why AF_UNIX on Windows, not named pipes

Since Windows 10 1803, Winsock supports `AF_UNIX` stream sockets natively
(`afunix.h`). Because they are real SOCKETs, the existing IOCP data path —
`WSASocketW`, `AcceptEx`, `WSARecv`/`WSASend`, the overlapped-op rooting
protocol — applies unchanged; .NET's socket engine drives afunix through the
same IOCP machinery. The one exception is connect: `ConnectEx` is a TCP-only
extension, so connect uses the ordinary Winsock `connect` (see "Windows
connect" below), exactly as Go and .NET do.

Named pipes are a different kernel object entirely: HANDLE-based
(`CreateNamedPipeW`/`ConnectNamedPipe`/`CreateFileW`), no sockaddr, per-instance
server handles, `ReadFile`/`WriteFile` overlapped I/O. Supporting them means a
parallel handle-based op path through `iopoll/iocp.jl` plus a
connect-retry-loop client (`WaitNamedPipeW`/`ERROR_PIPE_BUSY`). That is a real
transport of its own (this is how libuv's `uv_pipe` gets one API across
platforms), and the "future work" section sketches it — but nothing in the
motivating use cases (MySQL local socket, service IPC) needs it when AF_UNIX is
available. Interop with *existing* Windows pipe servers is the only thing that
would force it.

Consequence: on Windows versions before 1803, socket creation fails and
`Unix.connect`/`Unix.listen` throw the normalized
`SystemError("socket", EAFNOSUPPORT)` (Reseau maps `WSAEAFNOSUPPORT` to the
POSIX number in `_map_wsa_errno`), with the docstring noting the version
floor. No silent fallback.

## Public API

New exported module `Reseau.Unix` (file `src/3_unix.jl`), mirroring `TCP`:

```julia
module Unix

struct Conn <: NetCommon.StreamConn   # see "Sharing the stream method suite"
    fd::FD
end

mutable struct Listener
    fd::FD
    path::String            # caller's spelling, display only
    bind_path::String       # absolute identity used for bind AND cleanup; "" = abstract/never-unlink
    lock::ReentrantLock     # serializes cleanup, close, and the unlink setter
    unlink_enabled::Bool    # policy; guarded by `lock`
    cleanup_done::Bool      # once-guard; guarded by `lock`
end

connect(path::AbstractString)::Conn
listen(path::AbstractString; backlog::Integer = 128)::Listener
accept(listener::Listener)::Conn

local_addr(conn); remote_addr(conn); addr(listener)
set_deadline!(conn, ns); set_read_deadline!(conn, ns); set_write_deadline!(conn, ns)
set_deadline!(listener, ns)
set_read_buffer!(conn, n); set_write_buffer!(conn, n)   # SO_RCVBUF/SO_SNDBUF are family-generic
rawfd(conn); rawfd(listener)
closeread(conn); Base.closewrite(conn)
set_unlink_on_close!(listener, enabled::Bool)   # Go's SetUnlinkOnClose; see lifecycle
const DeadlineExceededError = IOPoll.DeadlineExceededError
end
```

All of the connection-level names above except `set_unlink_on_close!` are the
*same generics* as TCP's, owned by `NetCommon` after the hoist (see the
namespace contract below) — a `Unix.Conn` is usable anywhere a `TCP.Conn` is.

Plus the address type in `NetCommon`:

```julia
struct SocketAddrUnix <: SocketAddr
    path::String
end
```

### Path validation (public entry points)

- **Empty paths are rejected** (`ArgumentError`) by `Unix.connect` and
  `Unix.listen`. `SocketAddrUnix("")` is reserved as the *decoded* form of an
  unnamed endpoint (accepted peers, unbound clients); the family-only
  sockaddr builder exists but is internal. This sidesteps the platform
  divergence where Linux would autobind, BSD would reject, and Windows has no
  autobind. A Linux-only autobind API can be designed later without
  overloading the empty string.
- **Embedded NUL bytes in pathname addresses are rejected** (`ArgumentError`).
  The kernel would bind the prefix while display/equality/cleanup kept the
  full Julia string. (Linux *abstract* names may contain interior NULs —
  they are length-delimited; see below.)
- **Relative pathnames are absolutized** (`abspath`) before any syscall, and
  that absolute string is the single identity used for bind, connect,
  cleanup, and cache keys. This closes the `cd`-between-capture-and-bind /
  `cd`-before-close divergence family. Documented consequence: a short
  relative spelling fails if its absolute form exceeds `sun_path` (Go binds
  the relative spelling instead, but then the bind and cleanup identities
  can diverge — we choose the safe identity). This is a **lexical** absolute
  identity: `abspath` joins `pwd()` and normalizes but does not resolve
  symlinks, so the parent-directory/symlink topology must remain stable for
  the listener's lifetime (a retargeted parent symlink makes cleanup hit the
  new target), and two symlink spellings of one endpoint are distinct
  identities — including distinct TLS cache keys — by design. The
  caller-owned-directory advice is the safety boundary; canonical
  (`realpath`-of-parent) identity is deliberately not attempted in v1.
- **Length limits are checked in encoded bytes** (UTF-8), on the absolute
  form, and pathname vs abstract limits differ: pathnames get `sun_path`
  capacity minus the terminator (107 on Linux/Windows, 103 on macOS/BSD);
  Linux abstract names are length-delimited with no terminator, so `@` plus
  up to **107** name bytes (leading NUL + 107 = 108) is valid. Worth
  documenting loudly — macOS `TMPDIR` under `/var/folders/...` overflows the
  pathname limit easily; tests must use short paths.

### Semantics (Go parity unless noted)

- **Stale socket files**: `listen` does *not* auto-unlink an existing path;
  bind fails with `EADDRINUSE` exactly as Go does. Callers that own the path
  remove it first. (An `unlink_stale=true` convenience kwarg is tempting but
  racy and un-Go-like; leave it out of v1.)
- **Unlink on close**: see "Listener path lifecycle" below.
- **Abstract namespace (Linux only)**: a path starting with `'@'` maps to a
  leading NUL byte, no trailing NUL, `addrlen = offsetof(sun_path) + 1 + n`.
  Abstract names are decoded by `addrlen`, never by NUL search — interior
  NUL bytes round-trip. On macOS/BSD/Windows a leading `'@'` throws
  `ArgumentError`. *Deliberate Reseau restriction, not Go parity*: Go treats
  `@` as an ordinary pathname byte on BSD; we reject it so the same string
  cannot silently mean different things on different platforms. On Windows
  the abstract-namespace evidence is conflicting (Microsoft's announcement
  claims support, Go ships a Windows abstract builder, real-world reports
  show failures) — Reseau promises nothing there without a reliable Windows
  CI contract, so `@` stays Linux-only.
- **Nonblocking connect**: unix-socket connect either succeeds immediately or
  fails; a full listener backlog yields `EAGAIN` (Linux) / `ECONNREFUSED`
  (macOS, from XNU's `uipc_usrreq.c`) rather than `EINPROGRESS`. Mirror Go:
  surface `EAGAIN` as a hard `SystemError` instead of waiting (Go waits only
  on `EINPROGRESS`/`EALREADY`/`EINTR`; a backlog-full unix socket never
  becomes writable-pending). The existing `EINPROGRESS` wait path stays for
  kernels that do return it.
- **Peer addresses**: accepted and dialed client sockets are unnamed;
  `remote_addr` on an accepted conn is `SocketAddrUnix("")`, `local_addr` is
  the listener path. No getpeername round-trip needed on the accept fast path.
- **No TCP options**: `_apply_default_tcp_opts!` (TCP_NODELAY/SO_KEEPALIVE) is
  skipped for the unix family; `SO_REUSEADDR` is meaningless for unix binds
  and is never set. `set_nodelay!`/`set_keepalive!`/`set_linger!`/
  `set_quickack!` remain methods on `TCP.Conn` only — enforced by dispatch.

### Listener path lifecycle

Modeled on Go's `unixsock.go` (separate `unlink` policy + `unlinkOnce`), but
with an explicit lock instead of atomics: Go's own `sync.Once` semantics —
every caller *waits for the winning cleanup to finish* — are exactly what a
bare CAS/`@atomicswap` cannot provide (a second closer could reach
descriptor close while the first is still mid-unlink, reopening the
unlink-after-close window).

- `listen` resolves the **absolute** `bind_path` before any syscall (pathname
  addresses only; abstract/unnamed listeners store `""` and never unlink),
  and that exact string is used for bind *and* cleanup.
- Unlink eligibility exists only after **bind succeeds** (`bind` failing
  means the path belongs to someone else — never touch it). Any *later*
  construction failure (`listen_socket`, `register!`) runs the same cleanup
  before rethrowing (see listen sketch).
- All of close, the cleanup, and `set_unlink_on_close!` serialize through
  `listener.lock`:

```julia
function Base.close(listener::Listener)
    Base.@lock listener.lock begin
        if !listener.cleanup_done
            listener.cleanup_done = true
            if listener.unlink_enabled && !isempty(listener.bind_path)
                try
                    rm(listener.bind_path; force = true)   # unlink / DeleteFileW
                catch
                end
            end
        end
        # Still under the lock: no concurrent closer can reach descriptor
        # close while another is mid-unlink. close(fd) is idempotent.
        close(listener.fd)
    end
    return nothing
end

function set_unlink_on_close!(listener::Listener, enabled::Bool)
    Base.@lock listener.lock begin
        # Single contract: once cleanup has run (close began), this is a
        # documented NO-OP — it never re-arms a consumed once-guard, so a
        # second close can never delete a file someone recreated at the path.
        listener.cleanup_done && return nothing
        listener.unlink_enabled = enabled
    end
    return nothing
end
```

  `accept`/`isopen`/deadlines never take `listener.lock` (they go through the
  fd/fdlock layer as usual); the lock guards only path-cleanup policy, so
  holding it across the fd close cannot deadlock against in-flight accepts
  draining.
- Ordering: the once-guarded **unlink runs before descriptor close**.
  Unlinking first shrinks (but cannot eliminate) the cross-process window
  where another process binds the same path and our cleanup deletes *their*
  socket; that residual race is documented, matches Go, and the advice is to
  place sockets in a caller-owned directory.
- Unlink is **best-effort**: errors from `unlink`/`DeleteFileW` are
  swallowed (documented as such — the descriptor close must not be masked).
- The GC finalizer safety net closes only the descriptor and never touches
  the filesystem (same as Go): a leaked listener leaves a stale socket file.
  Documented explicitly.

## Internal design

### 1. `SocketOps`: sockaddr_un (~180 lines, pure code + tests)

```julia
@static if Sys.isbsd()          # macOS + BSDs: length-prefixed, 104-byte path
    struct SockAddrUn
        sun_len::UInt8
        sun_family::UInt8
        sun_path::NTuple{104, UInt8}
    end
else                            # Linux and Windows share the layout
    struct SockAddrUn
        sun_family::UInt16
        sun_path::NTuple{108, UInt8}
    end
end

# Builders return the struct *and* the effective addrlen; addrlen policy is
# platform-dependent (see below).
sockaddr_un(path::AbstractString)::Tuple{SockAddrUn, SockLen}
sockaddr_un_unnamed()::Tuple{SockAddrUn, SockLen}    # internal (decode identity, tests)

sockaddr_un_path(addr::SockAddrUn, addrlen::Integer)::String
```

addrlen policy:

- **POSIX pathname**: copy bytes, append NUL,
  `addrlen = offsetof(sun_path) + n + 1`; BSD additionally sets
  `sun_len = addrlen`.
- **Linux abstract** (`@name`): first path byte `0x00`, no trailing NUL,
  `addrlen = offsetof(sun_path) + 1 + n`, `n ≤ 107`.
- **Windows pathname**: full zero-filled struct,
  `addrlen = sizeof(SockAddrUn) = 110` — matching .NET, which always
  serializes the full 110-byte `SOCKADDR_UN` on Windows rather than the
  variable POSIX length. Paths are **UTF-8** (documented Windows afunix
  contract, also what .NET uses); limits are enforced on encoded bytes.

Decoding is **`addrlen`-bounded for every family**, not just abstract:
compute the usable slice as
`max(0, min(addrlen, sizeof(SockAddrUn)) - offsetof(sun_path))`; bytes past
the kernel-returned length are not response data and may be uninitialized.
Pathnames NUL-scan *within that slice only* (a peer may legally return an
unterminated pathname — then the whole slice is the name); abstract names
take the slice after the leading NUL verbatim (interior NULs preserved);
`addrlen ≤ offsetof(sun_path)` decodes to `""` (unnamed). Syscall storage
(`Ref{SockAddrUn}`) is zero-initialized. Tests: poisoned tail bytes,
truncated addrlen, and the no-terminator case.

Endpoint queries, following the existing `_in`/`_in6` pattern on all three
backends (thin `getsockname`/`getpeername` wrappers into a
`Ref{SockAddrUn}` + `Ref{SockLen}`):

```julia
get_socket_name_un(fd)::Tuple{SockAddrUn, SockLen}
get_peer_name_un(fd)::Tuple{SockAddrUn, SockLen}
```

These are the only new per-backend syscall wrappers required.

### 2. `NetCommon`: address plumbing + signature narrowing (~80 lines)

```julia
struct SocketAddrUnix <: SocketAddr
    path::String
end

_addr_family(::SocketAddrUnix)::Cint = SocketOps.AF_UNIX
Base.string(a::SocketAddrUnix) = isempty(a.path) ? "(unnamed)" : a.path
```

`_set_local_addr!` / `_set_remote_addr!` currently branch on
`family == AF_INET6` with an implicit IPv4 else; they gain an explicit
`family == AF_UNIX` branch that goes through `get_socket_name_un` /
`get_peer_name_un`. (`_to_sockaddr(::SocketAddrUnix)` is deliberately *not*
defined — unix dial/bind paths use the `(struct, addrlen)` pair, since a bare
struct value loses the abstract-namespace length.)

**Signature narrowing (lands as the first commit of U3, before the type
exists publicly)**: several existing IP-only entry points dispatch on the
abstract `SocketAddr` — `TCP.connect(::SocketAddr)` /
`TCP.connect(::SocketAddr, ::SocketAddr)`, `TCP.listen(::SocketAddr)`,
`TCP.listenany(::SocketAddr)`, `UDP.listen`/`UDP.connect`/`UDP.sendto`, the
direct-address TLS conveniences, **and the resolver-backed
`UDP.connect(network, address; local_addr::…SocketAddr)` keyword** (a unix
value would otherwise ride the keyword into an IP-only resolution path).
Without narrowing, a `SocketAddrUnix` would dispatch into IP logic and die
deep inside on the missing `_to_sockaddr`. These signatures narrow to the
existing IP-only `SocketEndpoint = Union{SocketAddrV4, SocketAddrV6}` alias,
so a unix address fails at the boundary: `MethodError` for positional
arguments, `TypeError` for typed keywords (Julia does not dispatch on
keyword values — the tests pin each form's actual error). Narrowing breaks
no supported caller: V4/V6 are the only shipped `SocketAddr` subtypes.
Abstract `SocketAddr` remains for storage (`FD.laddr/raddr`), display, and
genuinely family-generic returns. The narrowing commit lands first; the
negative applicability tests land with the commit that introduces
`SocketAddrUnix` (they cannot compile earlier).

### 3. Sharing the stream method suite (the one real refactor)

Decided: introduce `NetCommon.StreamConn <: IO` with the seam
`netfd(c::StreamConn)::FD`; `TCP.Conn` and `Unix.Conn` are one-field concrete
subtypes. The migration is *mechanical but not verbatim*: every moved method
body changes `conn.fd` → `netfd(conn)`. The `3_tcp.jl` tail is not one
generic suite; it partitions as:

| Category | Members (today in `3_tcp.jl`) | Destination |
| --- | --- | --- |
| Base IO on the connection | `unsafe_read`, `readbytes!`, `read(::…, nb)`, `read(::…, UInt8)`, `readavailable`, `eof`, `isopen`, `flush`, all `write`/`unsafe_write` overloads, `close`, `closewrite` | `StreamConn` methods in NetCommon |
| Internal helpers those methods bottom out in | `_read_some!`, `_grow_readbytes_target!`, `_readbytes_all!`, `_readbytes_some!`, `_peek_eof`, `_write_rooted!`, `_rawfd(::FD)`, `_positive_sockopt_value` | move to NetCommon with their callers (a NetCommon-defined method resolves helper names in NetCommon — TCP-local helpers would break `Unix.Conn`); TCP's keepalive code imports `_positive_sockopt_value` back |
| Custom connection generics | `set_deadline!`, `set_read_deadline!`, `set_write_deadline!`, `closeread`, `rawfd`, `local_addr`, `remote_addr`, `set_read_buffer!`, `set_write_buffer!` | generics move to NetCommon, methods on `StreamConn` |
| Shared fd helper | `Base.close(::FD)` | NetCommon (it is already about `FD`) |
| Listener methods | `close`, `isopen`, `set_deadline!`, `rawfd`, `addr`, `local_addr` for `TCP.Listener` | stay in TCP; `Unix.Listener` gets its own thin copies (listeners are per-transport types with different lifecycle — see path lifecycle) |
| TCP-only socket options | `set_nodelay!`, `set_keepalive!`, `set_quickack!`, `set_linger!`, `_apply_default_tcp_opts!` | stay in TCP on `TCP.Conn` |

**Namespace contract**: the custom generics become NetCommon functions; `TCP`
and `Unix` both do `import ..NetCommon: set_deadline!, closeread, rawfd, ...`
so `TCP.set_deadline!` (every existing qualified call site and doc reference)
remains the same binding, and `Unix.set_deadline!` is that binding too. Base
methods stay Base bindings regardless of which module defines them. Each
module keeps its `DeadlineExceededError` alias (already the same
`IOPoll.DeadlineExceededError` binding today). Hoist lands as its own
behavior-preserving commit with a zero-diff full test run, plus a shared
stream-conformance test factory (same IO/deadline/half-close/buffer/rawfd/
repeated-close checks run against both concrete transports).

#### TLS migration (the union)

The transport field widens to a small concrete union rather than a type
parameter:

```julia
const StreamTransport = Union{TCP.Conn, Unix.Conn}
```

A two-element union of concrete single-field structs keeps `TLS.Conn`
non-parametric (zero churn for downstream annotations and containers), and
Julia union-splits accesses of the field, so the hot record paths stay direct
calls. The migration is staged as **two mechanical commits in U4**:

1. **Rename** the field `tcp` → `stream` across TLS — all `.tcp` field uses
   under `src/5_tls.jl` and `src/tls/` (currently 52 occurrences across six
   files, including the tls12/tls13 *handshake* files, not just the record
   files; regenerate the inventory with `rg '\.tcp\b'` immediately before
   the commit), type unchanged, zero test diffs.
2. **Widen** to `StreamTransport` and migrate the transport-typed surfaces.

Declaration-order note: `5_tls.jl` includes the record files *before* the
`Conn` struct is declared, so `StreamTransport` (which needs `TCP.Conn` and
`Unix.Conn` imported) must be defined ahead of those includes.

Inventory of transport-typed surfaces that widen (beyond the field itself):
the `_new_native_*` constructors, `client`/`server` entry points, `net_conn`
(declared `::TCP.Conn` today), `_tls13_has_resumable_session` /
`_tls12_has_resumable_session`, `_show_closed` and the other helpers that
reach through `conn.tcp.fd.pfd` directly, the record-layer read/write helpers
that take the transport explicitly, and the public forwarding methods that
call `TCP.set_deadline!`/`TCP.local_addr`/`TCP.remote_addr` (these become the
NetCommon generics — free after the hoist).

**Session-cache keys** get explicit, disjoint domains. Today's
`_tls13_client_session_cache_key` handles the IPv4 case then *type-asserts*
`SocketAddrV6` — a unix peer without `server_name` would throw a `TypeError`.
New scheme: every key is domain-tagged — `sni:<name>`, `ip:<addr:port>`,
`unix-path:<absolute-bind-identity>`, `unix-abstract:<name-bytes>` — so a
socket file literally named `example.com:443` cannot collide with an SNI or
IP key, and the unix identity is the same absolute path the dial actually
used (stable across `cd`, per the path-validation rules). Unnamed endpoints
skip resumption. Retagging invalidates existing in-process cache entries
once; harmless.

**Scope**: v1 supports `TLS.client`/`TLS.server` over an established
`Unix.Conn`. `TLS.Listener` stays TCP-backed; widening it is trivial later
but is not implied here.

A TLS-over-unix handshake/echo test lands **in U4 with the union change**,
exercising both union members so the union-split paths are compiled and
checked — not deferred to the polish milestone.

#### SOCKS migration

`Reseau.SOCKS` is the other in-repo stream consumer: its handshake uses only
reads, writes, and the deadline generic — nothing TCP-specific — yet all
seven of its stream-taking signatures currently require `TCP.Conn`, which
would make "usable anywhere a `TCP.Conn` is" false at dispatch. Those
signatures widen to `NetCommon.StreamConn` in **U2** (behavior-preserving —
they only touch the hoisted surface; existing SOCKS tests keep running over
`TCP.Conn`, preserving the zero-diff gate). SOCKS-over-unix is genuinely
useful, not just claim-hygiene: Tor, for one, exposes its SOCKS listener on
a unix socket. An end-to-end SOCKS handshake over `Unix.Conn` lands in U3,
and the same transport-neutral case runs on Windows CI in U5.

### 4. The `Unix` module itself (~400 lines with docstrings)

Dial (POSIX) — public `connect(path)` forwards to an internal impl that
threads `connect_deadline_ns::Int64 = 0` and `cancel_state = nothing`
positionally, mirroring `_connect_socketaddr_impl`'s shape so future dial
policy / cancellation can pass real values; the v1 public API exposes
neither (same as `TCP.connect(remote_addr)`):

```julia
function _connect_unix_impl(path::String, connect_deadline_ns::Int64, cancel_state)::Conn
    remote = SocketAddrUnix(path)   # path pre-validated + absolutized
    fd = open_net_fd!(; family = SocketOps.AF_UNIX, sotype = SocketOps.SOCK_STREAM, net = :unix)
    try
        sa, salen = SocketOps.sockaddr_un(remote.path)
        sa_ref = Ref(sa)
        errno = GC.@preserve sa_ref SocketOps.connect_socket(
            fd.pfd.sysfd, Base.unsafe_convert(Ptr{Cvoid}, sa_ref), salen)
        if errno == Int32(0) || errno == Int32(Base.Libc.EISCONN)
            IOPoll.register!(fd.pfd)
            fd.laddr = SocketAddrUnix("")      # clients are unnamed
            fd.raddr = remote
            @atomic :release fd.is_connected = true
            return Conn(fd)
        end
        _is_connect_pending_errno(errno) || throw(SystemError("connect", Int(errno)))
        IOPoll.register!(fd.pfd)
        _wait_connect_complete!(fd, remote, cancel_state)   # existing SO_ERROR wait loop
        return Conn(fd)
    catch
        close(fd)
        rethrow()
    end
end
```

#### Windows connect

`ConnectEx` does not support afunix (r1 finding 1), so Windows unix dial uses
the ordinary nonblocking Winsock `connect` — the wrapper already exists
(`connect_socket`, `socket_ops/windows.jl:664`). Go ships the equivalent
(`connectFunc`) for every non-TCP network; .NET does the same via
`WSAConnect`. Afunix connects are local: success, `ECONNREFUSED`, and
`ENOENT` are immediate in the overwhelmingly common case and no waiting
machinery runs. The design point is the rare pending connect
(`WSAEWOULDBLOCK`), because IOCP is completion-based and has no readiness
notification for a plain connect. Two constraints shape the wait (r2
findings 2–3):

- **Scheduler-cooperative**: a gcsafe blocking ccall does not yield to the
  Julia scheduler — a blocking `select` slice would pin a worker thread and
  could starve a same-thread closer indefinitely. So the wait is a
  **zero-timeout `select` probe + `sleep(0.01)` loop**: the probe never
  blocks (timeout `{0,0}`), and `sleep` is a real scheduler yield, so close/
  deadline observability holds at sleep granularity and no worker thread is
  ever occupied. (`Base.@threadcall select` with a real timeout is a
  possible later refinement; it buys latency on a path that is rare by
  construction at the cost of threadpool/trim validation, so not v1.)
- **Socket lifetime**: the whole sequence — initial `connect`, every probe,
  the final `SO_ERROR` read — runs under the FD **write lock**
  (`_fd_write_lock!` … `finally` unlock), exactly like `IOPoll.connect!`.
  The lock holds the descriptor reference, so a concurrent `close` cannot
  destroy and recycle the `SOCKET` value while it sits in an `fd_set`;
  close marks the fd closing and waits, the loop observes
  `_fdlock_closing` on its next iteration, errors out, and releases the
  lock.

The loop, specified (Winsock facts: `select` reports nonblocking-connect
success via `writefds` and failure via `exceptfds`; it **mutates** the sets,
so both are rebuilt every iteration; Windows `fd_set` is
`u_int fd_count; SOCKET fd_array[64]` — an array, not a POSIX bitmap, so
`FD_SETSIZE == 64` is capacity, and `nfds` is ignored, pass 0; entries are
native-width `SOCKET`, i.e. Reseau's `SocketFD = UInt`):

1. **Gate first, every iteration** — matching the IOCP wait rule that a
   published close/deadline error beats readiness: check, in order,
   `_fdlock_closing` (→ the standard closing error), the deadline
   (`connect_deadline_ns != 0 && time_ns() >= connect_deadline_ns` →
   `DeadlineExceededError`), and the `cancel_state` hook (no-op stub today,
   checked per iteration so real cancellation is inherited when that design
   lands — **no cancellation behavior is claimed or tested in v1**). The
   gates run before every probe *and again on ready branches* (steps 3 and
   5): a ready socket must never let success outrun a close or deadline
   that has already been published.
2. Rebuild `writefds` and `exceptfds` (`fd_count = 1`, our socket) and a
   zero `timeval`; call `select(0, C_NULL, writefds, exceptfds, timeout)`.
   `SOCKET_ERROR` → map `WSAGetLastError()` through `_map_wsa_errno` →
   `SystemError("select", mapped)`.
3. Membership, **exception set first — it takes precedence in the
   both-sets case**: re-run the step-1 gates, then read `SO_ERROR` once and
   **map it through `_map_wsa_errno` before anything else** (Windows
   `get_socket_error` returns raw WSA numbers; unmapped `10061` renders as
   "Unknown error"). Except-ready → mapped nonzero is
   `SystemError("connect", mapped)`; mapped `0` is a stable
   `SystemError("connect", EIO)` (never silently succeed a failed connect).
   Write-ready only → mapped `0` or `EISCONN` is success; mapped nonzero is
   `SystemError("connect", mapped)`.
4. Neither set ready → `sleep(0.01)`, continue.
5. On success only: `IOPoll.register!` runs, exactly once, and then the
   **fdlock closed bit is rechecked**: if close won before or during
   registration, throw the standard closing error and let the
   `finally`/unlock path destroy and deregister the fd — a `Conn` whose
   close has already begun must never be returned. (The plain
   connect/select sequence is legal on a nonblocking overlapped-capable
   socket because no `OVERLAPPED` is supplied; IOCP association happens
   only after completion.)

Cross-arch note: the `fd_set`/`timeval` FFI structs get x64/arm64 layout
assertions in the unit tests.

Empirical item for U5: afunix behavior on a full backlog (immediate refuse
vs `WSAEWOULDBLOCK`) is undocumented; the pending path handles either, and a
CI test pins whichever it is.

Listen — one absolute identity, non-throwing teardown:

```julia
function listen(path::AbstractString; backlog::Integer = 128)::Listener
    p = _check_bind_path(path)              # rejects "", NULs-in-pathnames, '@' off-Linux
    is_abstract = startswith(p, '@')
    bind_path = is_abstract ? p : abspath(p)   # THE identity: bind, cleanup, cache keys
    _check_encoded_length(bind_path)
    local_addr = SocketAddrUnix(bind_path)
    fd = open_net_fd!(; family = SocketOps.AF_UNIX, sotype = SocketOps.SOCK_STREAM, net = :unix)
    bound = false
    try
        sa, salen = SocketOps.sockaddr_un(bind_path)
        sa_ref = Ref(sa)
        GC.@preserve sa_ref SocketOps.bind_socket(
            fd.pfd.sysfd, Base.unsafe_convert(Ptr{Cvoid}, sa_ref), salen)
        bound = true                       # only now do we own the path
        SocketOps.listen_socket(fd.pfd.sysfd, backlog)
        IOPoll.register!(fd.pfd)
        fd.laddr = local_addr
        cleanup = is_abstract ? "" : bind_path
        return Listener(fd, String(path), cleanup, ReentrantLock(), !isempty(cleanup), false)
    catch
        # Teardown must not mask the primary error: bind succeeded means the
        # path is ours to remove; every cleanup step is swallowed.
        if bound && !is_abstract
            try
                rm(bind_path; force = true)
            catch
            end
        end
        try
            close(fd)
        catch
        end
        rethrow()
    end
end
```

Accept reuses `IOPoll.accept!(fd, AF_UNIX, SOCK_STREAM)` unchanged; the peer
decode returns `nothing` for unix sockaddrs, and instead of falling back to a
getpeername round-trip the unix accept sets `raddr = SocketAddrUnix("")` and
`laddr = listener path` directly. No `_apply_default_tcp_opts!`.

### 5. Windows specifics

Confirmed by construction / by the survey (nothing to write):

- `WSASocketW(AF_UNIX, SOCK_STREAM, 0, WSA_FLAG_OVERLAPPED)` — the existing
  `open_socket` already does this given `family = AF_UNIX`.
- `AcceptEx`/`WSARecv`/`WSASend` on afunix sockets — supported (this is
  .NET's data path for UDS on Windows).
- AcceptEx address slots: 128 bytes each ≥ `sizeof(SOCKADDR_UN) + 16 = 126`.
- `decode_sockaddr_raw`/`GetAcceptExSockaddrs` returning `nothing` for the
  unix family is already the accept path's fallback branch.

Windows-specific work items (all in U5):

1. The connect path above (the only structural piece).
2. Full-struct 110-byte addrlen serialization + UTF-8 path encoding with
   multibyte-boundary length tests.
3. `DeleteFileW`-based cleanup via `rm` (afunix socket files are
   reparse-point files; `rm(; force=true)` handles them).
4. Backlog-full behavior pinned by test (see above).
5. CI on `windows-latest` **asserts the capability probe succeeds** — a
   skip-if-unsupported gate would silently hide regressions on a platform
   where afunix is expected to exist. The skip applies only to older
   self-hosted images, if any.

## Future work (explicitly deferred)

- **Two-string dial surface** (`connect("unix", path)`): requires deciding an
  owning module for a transport-neutral generic (today's two-string methods
  are `TCP.connect`/`TCP.listen` returning TCP types), widening `OpError`'s
  endpoint fields beyond the IP-only `SocketEndpoint` union, and defining
  every dial keyword (`timeout_ns`, `local_addr`, `fallback_delay_ns`,
  `resolver`, `policy`) for a path-shaped address. Separate small design.
- **Linux autobind**: an explicit API (`Unix.listen_autobind()`-style), not
  an empty-string overload.
- **`socketpair`** (POSIX + Windows-emulated): trivial once `Unix.Conn`
  exists; useful for tests and child-process IPC.
- **SCM_RIGHTS fd passing**: `MsgHdr`/`sendmsg`/`recvmsg` wrappers already
  exist; needs cmsg builders and `send_fds`/`recv_fds` on `Unix.Conn`
  (POSIX-only; Windows uses `WSADuplicateSocket` instead — separate design).
- **Peer credentials**: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED`+`LOCAL_PEERPID`
  (macOS) as a `peer_credentials(conn)` query, for socket-authenticated
  servers.
- **`unixgram`**: mirror the `UDP` module shape if demand ever appears.
- **Windows named pipes**: a separate `NamedPipe` transport implementing the
  same high-level `IO` contract. Note it would *not* get the stream suite
  merely by subtyping `StreamConn`: the shared methods bottom out in
  socket-only primitives (`recv(MSG_PEEK)` for eof, `shutdown` for
  half-close, `RawFD`/`WindowsRawSocket` for rawfd), so a pipe transport
  needs handle-specific read/EOF/half-close/raw-handle seams plus a
  handle-based (non-WSA) op variant in `iopoll/iocp.jl`: per-instance
  `CreateNamedPipeW(PIPE_TYPE_BYTE, FILE_FLAG_OVERLAPPED)` + overlapped
  `ConnectNamedPipe` as the "accept"; client `CreateFileW` +
  `WaitNamedPipeW` retry on `ERROR_PIPE_BUSY`; I/O via overlapped
  `ReadFile`/`WriteFile`. Only worth building against a concrete consumer.

## Test plan

- **sockaddr_un unit tests** (pure, everywhere): round-trip build/decode;
  pathname vs abstract limits at the exact boundary and one byte over;
  UTF-8 multibyte truncation boundaries; abstract names with interior NULs
  round-tripping by addrlen; unnamed decode; rejection of empty paths,
  embedded NULs **in pathname inputs**, and `@` off-Linux; Windows
  full-struct addrlen; addrlen-bounded decode (poisoned tail bytes,
  truncated addrlen, unterminated pathname); Windows `fd_set`/`timeval`
  layout assertions.
- **Refactor gate (U2)**: the `StreamConn` hoist (including the internal
  helper row of the migration table) lands with a zero-diff full test run,
  plus the shared stream-conformance factory (IO, deadline, half-close,
  buffer setters, rawfd, repeated close) run against `TCP.Conn`;
  `Unix.Conn` joins the same factory in U3.
- **Negative applicability (U3, type-introduction commit)**:
  `SocketAddrUnix` passed to `TCP.connect`/`TCP.listen`/`TCP.listenany`,
  the UDP entry points (including the resolver-backed `local_addr`
  keyword), and the direct-address TLS conveniences fails at the narrowed
  boundary — `MethodError` for positionals, `TypeError` for typed keywords
  — not deep inside the dial path.
- **Lifecycle tests (U3)**: `EADDRINUSE` on stale file; unlink-on-close and
  its opt-out; **post-bind failure cleanup** (inject `listen_socket`
  failure, assert the path is removed and the primary error propagates);
  **relative-path identity** (dial and listen with a relative spelling,
  `cd`, close — the absolutized path is unlinked, nothing else);
  repeated close; concurrent close (two tasks; exactly one unlink, fd close
  strictly after cleanup); `set_unlink_on_close!` before close and racing
  close (post-cleanup it is a no-op — a file recreated at the path survives
  a second close); finalizer contract (leaked listener: fd closed, path
  intentionally stale).
- **Integration (POSIX in U3, Windows in U5)**: connect/accept/echo;
  moderate-size transfer plus a *unit* test of the 1 GiB chunk boundary (the
  routine >1 GiB wire transfer moves to a dedicated stress lane, not normal
  CI); eof probe; deadlines; closeread/closewrite; concurrent accept storm;
  **bounded** backlog saturation (fill a known-size queue with a cap,
  assert Linux `EAGAIN` vs macOS `ECONNREFUSED`); peer close during pending
  I/O.
- **BSD**: U3's integration suite runs on the existing FreeBSD CI lane, not
  just Linux/macOS (the scope says BSD; the CI already exists).
- **Abstract namespace** round-trip incl. interior NUL (Linux CI only).
- **TLS-over-unix (U4)**: handshake + echo over both `StreamTransport` union
  members; session-resumption key domains (sni vs unix-path disjointness,
  the absolute-path identity, unnamed-peer skip, and the pre-fix
  `TypeError` case as a regression test).
- **SOCKS**: existing SOCKS-over-TCP tests unchanged through U2's widening;
  end-to-end SOCKS handshake over `Unix.Conn` (U3); same transport-neutral
  case on Windows CI (U5).
- **Windows (U5)**: probe asserted true on `windows-latest`; pending-connect
  deadline and close observability (no cancellation claims in v1); Unicode
  path round-trip; full-size sockaddr; `DeleteFileW` cleanup; backlog-full
  behavior pinned; repeated concurrent full-duplex traffic under the suite's
  hang watchdog.
- **Trim + precompile (U6)**: a Unix entry in the trim-safe workload list
  (`test/trim_compile_tests.jl` pattern) and a short-path precompile
  workload following the existing rule that every blocking step gets a
  bounded deadline and `finally` cleanup (a precompile hang blocks
  `Pkg.add`).

## Milestones

1. **U1 — sockaddr_un + endpoint queries** (`SocketOps`, all backends): pure
   address code + unit tests. No public API change.
2. **U2 — StreamConn hoist**: behavior-preserving migration per the method
   table — Base methods *and* the internal helpers they bottom out in —
   with bodies mechanically `conn.fd` → `netfd(conn)`; namespace contract
   via `import ..NetCommon:` so every `TCP.*` qualified name keeps working;
   the seven SOCKS stream signatures widen to `StreamConn`; conformance
   factory. Zero test diffs required. TLS untouched.
3. **U3 — Unix module, POSIX**: first commit narrows IP-only signatures to
   `SocketEndpoint` (negative tests follow with the type commit); then
   `SocketAddrUnix`, `Unix` types
   compiling on **all** platforms (Windows sources load and precompile;
   runtime support arrives in U5), POSIX connect/listen/accept, path
   validation + absolutized identity, lock-based listener lifecycle,
   SOCKS-over-unix handshake test, docs; Linux + macOS + FreeBSD CI green.
4. **U4 — TLS transport union**: commit 1 renames the `tcp` field to
   `stream` (mechanical, ~51 sites, zero test diffs); commit 2 declares
   `StreamTransport` ahead of the record includes, widens the full inventory
   (constructors, `net_conn`, resumable-session helpers, `_show_closed`,
   record helpers, forwarding), lands the domain-tagged session-cache keys
   and TLS-over-unix tests. First correctness evidence for the union lands
   here, not in polish.
5. **U5 — Windows afunix**: the probe-loop connect path under the fd write
   lock, full-struct/UTF-8 serialization, lifecycle on NTFS,
   probe-asserting CI, the transport-neutral SOCKS case.
6. **U6 — polish**: precompile workload entry, trim-safe workload, README/
   docs, `live_demos.jl` sample, stress lane.

U1 and U2 are independent and can land in either order; U3 depends on both;
U4 and U5 depend on U3 and are independent of each other.
