# FDLock state bits packed into one atomic word (close flag, lock flags, refs, waiter counts).
const _MUTEX_CLOSED = UInt64(1) << 0
const _MUTEX_RLOCK = UInt64(1) << 1
const _MUTEX_WLOCK = UInt64(1) << 2
const _MUTEX_REF = UInt64(1) << 3
const _MUTEX_REF_MASK = (UInt64(1) << 20 - UInt64(1)) << 3
const _MUTEX_RWAIT = UInt64(1) << 23
const _MUTEX_RMASK = (UInt64(1) << 20 - UInt64(1)) << 23
const _MUTEX_WWAIT = UInt64(1) << 43
const _MUTEX_WMASK = (UInt64(1) << 20 - UInt64(1)) << 43

const _POLL_NO_ERROR = Int32(0)
const _POLL_ERR_CLOSING = Int32(1)
const _POLL_ERR_TIMEOUT = Int32(2)
const _POLL_ERR_NOT_POLLABLE = Int32(3)

"""
Bitmask of operations used for readiness waits and deadline management.

`READWRITE` is intentionally the bitwise OR of `READ` and `WRITE` so callers can
test or combine directions cheaply.
"""
@enumx PollOp::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end

struct NetClosingError <: Exception end
struct FileClosingError <: Exception end
struct NoDeadlineError <: Exception end
struct DeadlineExceededError <: Exception end
struct NotPollableError <: Exception end

function Base.showerror(io::IO, ::NetClosingError)
    print(io, "use of closed network connection")
    return nothing
end

function Base.showerror(io::IO, ::FileClosingError)
    print(io, "use of closed file")
    return nothing
end

function Base.showerror(io::IO, ::NoDeadlineError)
    print(io, "file type does not support deadline")
    return nothing
end

function Base.showerror(io::IO, ::DeadlineExceededError)
    print(io, "i/o timeout")
    return nothing
end

function Base.showerror(io::IO, ::NotPollableError)
    print(io, "not pollable")
    return nothing
end

@inline function _closing_error(is_file::Bool)::Exception
    is_file && return FileClosingError()
    return NetClosingError()
end

@inline function _mode_has_read(mode::PollOp.T)::Bool
    return (UInt8(mode) & UInt8(PollOp.READ)) != 0
end

@inline function _mode_has_write(mode::PollOp.T)::Bool
    return (UInt8(mode) & UInt8(PollOp.WRITE)) != 0
end

@inline function _is_accept_retry_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINTR) || errno == Int32(Base.Libc.ECONNABORTED)
end

@inline function _monotonic_ns()::Int64
    return Int64(time_ns())
end
