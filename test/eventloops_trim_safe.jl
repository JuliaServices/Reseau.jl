using Reseau

const NP = Reseau.EventLoops
const IP = Reseau.IOPoll

@static if !Sys.iswindows()

function _socketpair_stream()::Tuple{Cint, Cint}
    fds = Vector{Cint}(undef, 2)
    ret = ccall(:socketpair, Cint, (Cint, Cint, Cint, Ptr{Cint}), Cint(1), Cint(1), Cint(0), pointer(fds))
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _close_fd(fd::Cint)::Nothing
    fd < 0 && return nothing
    ccall(:close, Cint, (Cint,), fd)
    return nothing
end

function _write_byte(fd::Cint, b::UInt8)::Nothing
    buf = Ref{UInt8}(b)
    n = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf, Csize_t(1))
    n == Cssize_t(1) || throw(SystemError("write", Int(Base.Libc.errno())))
    return nothing
end

@inline function _expect_errno_zero(errno::Int32, op::AbstractString)::Nothing
    errno == Int32(0) || throw(SystemError(op, Int(errno)))
    return nothing
end

function run_eventloops_trim_sample()::Nothing
    (Sys.isapple() || Sys.islinux()) || return nothing
    state = NP.Poller()
    fd0 = Cint(-1)
    fd1 = Cint(-1)
    backend_open = false
    try
        _expect_errno_zero(NP._backend_init!(state), "event loop kqueue init")
        backend_open = true
        fd0, fd1 = _socketpair_stream()
        token = UInt64(1)
        registration = NP.Registration(fd0, token, NP.PollMode.READWRITE, NP.PollWaiter(), NP.PollWaiter(), false)
        state.registrations[fd0] = registration
        state.registrations_by_token[token] = registration
        _expect_errno_zero(NP._backend_open_fd!(state, fd0, NP.PollMode.READWRITE, token), "event loop open fd")
        _write_byte(fd1, 0x44)
        _expect_errno_zero(NP._backend_poll_once!(state, Int64(0)), "event loop poll once")
        NP.pollwait!(registration.read_waiter)
        _expect_errno_zero(NP._backend_close_fd!(state, fd0), "event loop close fd")
    finally
        _close_fd(fd0)
        _close_fd(fd1)
        backend_open && NP._backend_close!(state)
    end
    return nothing
end

function run_internal_poll_trim_sample()::Nothing
    (Sys.isapple() || Sys.islinux()) || return nothing
    fd0, fd1 = _socketpair_stream()
    ipfd = IP.FD(fd0)
    fd0 = Cint(-1)
    try
        IP.init!(ipfd; pollable = false)
        _write_byte(fd1, 0x65)
        read_buf = Vector{UInt8}(undef, 1)
        n = IP.read!(ipfd, read_buf)
        n == 1 || error("expected one byte read")
        read_buf[1] == 0x65 || error("unexpected read byte")
        n = IP.write!(ipfd, UInt8[0x66])
        n == 1 || error("expected one byte written")
        peer = Ref{UInt8}(0x00)
        peer_n = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd1, peer, Csize_t(1))
        peer_n == Cssize_t(1) || throw(SystemError("read", Int(Base.Libc.errno())))
        peer[] == 0x66 || error("unexpected peer byte")
        try
            IP.set_read_deadline!(ipfd, Int64(1))
            error("expected NoDeadlineError for non-pollable fd")
        catch err
            err isa IP.NoDeadlineError || rethrow(err)
        end
    finally
        ipfd.sysfd >= 0 && close(ipfd)
        _close_fd(fd1)
    end
    return nothing
end

else

function run_eventloops_trim_sample()::Nothing
    return nothing
end

function run_internal_poll_trim_sample()::Nothing
    return nothing
end

end

function @main(args::Vector{String})::Cint
    _ = args
    try
        run_eventloops_trim_sample()
        run_internal_poll_trim_sample()
    finally
        NP.shutdown!()
    end
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
