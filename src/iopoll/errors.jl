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

@inline function _is_accept_retry_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINTR) || errno == Int32(Base.Libc.ECONNABORTED)
end
