using Reseau

const NP = Reseau.IOPoll

function run_iopoll_runtime_trim_sample()::Nothing
    waiter = NP.PollWaiter()
    NP.pollnotify!(waiter, NP.PollWakeReason.READY) && error("unexpected waiter wake state")
    NP.pollwait!(waiter) == NP.PollWakeReason.READY || error("expected READY wake reason")

    registration = NP.Registration(Cint(7), UInt64(11), NP.PollMode.READWRITE, NP.PollWaiter(), NP.PollWaiter(), false)
    combined = NP._build_deadline_entries(registration.pollstate, Int64(10), Int64(10), UInt64(3), UInt64(5))
    length(combined) == 1 || error("expected one combined deadline entry")
    combined[1].mode == NP.PollMode.READWRITE || error("expected combined read/write entry")

    split = NP._build_deadline_entries(registration.pollstate, Int64(10), Int64(11), UInt64(3), UInt64(5))
    length(split) == 2 || error("expected split deadline entries")
    split[1].mode == NP.PollMode.READ || error("expected read deadline entry")
    split[2].mode == NP.PollMode.WRITE || error("expected write deadline entry")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_iopoll_runtime_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
