module NativeThreadLifetimeTests

using Test
using Reseau

const HR = Reseau.HostResolvers
const IP = Reseau.IOPoll
const resolver_entry = HR._ADDRINFO_THREAD_ENTRY_C[]
const poller_entry = IP._POLLER_THREAD_ENTRY_C[]
const gate_condition = Threads.Condition()

mutable struct EntryGate
    arrived::Int
    completed::Int
    released::Bool
    reference::Union{Nothing,WeakRef}
end

# Keys are raw native arguments; the gate must not keep their Julia objects alive.
const gates = Dict{Ptr{Cvoid},EntryGate}()

function gated_entry(arg::Ptr{Cvoid}, callback::Ptr{Cvoid})::Ptr{Cvoid}
    lock(gate_condition)
    gate = try
        value = get!(() -> EntryGate(0, 0, false, nothing), gates, arg)
        value.arrived += 1
        while !value.released
            wait(gate_condition)
        end
        value
    finally
        unlock(gate_condition)
    end
    try
        queue = gate.reference === nothing ? nothing : gate.reference.value
        # A failed lifetime assertion must not make the test dereference freed memory.
        gate.reference !== nothing && queue === nothing && return C_NULL
        return GC.@preserve queue ccall(callback, Ptr{Cvoid}, (Ptr{Cvoid},), arg)
    finally
        lock(gate_condition) do
            gate.completed += 1
        end
    end
end

resolver_gate(arg::Ptr{Cvoid})::Ptr{Cvoid} = gated_entry(arg, resolver_entry)
poller_gate(arg::Ptr{Cvoid})::Ptr{Cvoid} = gated_entry(arg, poller_entry)

function gate_count(arg, completed=false)
    lock(gate_condition) do
        gate = get(gates, arg, nothing)
        gate === nothing && return 0
        return completed ? gate.completed : gate.arrived
    end
end

function release_gate(arg)
    lock(gate_condition) do
        gates[arg].released = true
        notify(gate_condition; all=true)
    end
end

function wait_gate(arg, count; completed=false)
    @test timedwait(() -> gate_count(arg, completed) == count, 10.0; pollint=0.001) == :ok
end

Base.@noinline function queue_reference()
    queue = HR._ADDRINFO_WORK_QUEUE[]
    reference, arg = WeakRef(queue), pointer_from_objref(queue)
    lock(gate_condition) do
        gates[arg] = EntryGate(0, 0, false, reference)
    end
    return reference, arg
end

Base.@noinline function start_pool()
    HR._ensure_addrinfo_pool!()
    return nothing
end

Base.@noinline alive(reference) = reference.value !== nothing

function collect_queue(reference)
    return timedwait(5.0; pollint=0.01) do
        GC.gc(true)
        !alive(reference)
    end
end

# Inject errors at the creation boundary. The creation case starts no OS thread;
# the detach case delegates to the real native helper before returning an error.
const spawn_failure = Ref(:none)
const native_starts = Ref(0)
function IP._spawn_detached_thread(
        name::String,
        callback::Ref{Ptr{Cvoid}},
        arg::Union{Channel{HR._AddrInfoFuture},IP.Poller},
    )
    failure = spawn_failure[]
    spawn_failure[] = :none
    failure == :create && throw(SystemError("native thread creation", Int(Base.Libc.EAGAIN)))
    status = invoke(IP._spawn_detached_thread, Tuple{AbstractString,Ref{Ptr{Cvoid}},Any}, name, callback, arg)
    native_starts[] += 1
    return failure == :detach ? Cint(Base.Libc.EINVAL) : status
end
const injected_method = which(IP._spawn_detached_thread, (String,Ref{Ptr{Cvoid}},IP.Poller))

@testset "native thread argument lifetime" begin
    HR.shutdown!()
    IP.shutdown!()
    HR._ADDRINFO_THREAD_ENTRY_C[] = @cfunction(resolver_gate, Ptr{Cvoid}, (Ptr{Cvoid},))
    try
        @testset "retired queue generations outlive shutdown" begin
            first, first_arg = queue_reference()
            start_pool()
            wait_gate(first_arg, HR._ADDRINFO_POOL_SIZE)
            shutdown_task = @async HR.shutdown!()
            @test timedwait(() -> HR._ADDRINFO_STARTED_THREADS[] == 0, 1.0) == :ok
            @test !istaskdone(shutdown_task)
            GC.gc(true)
            @test alive(first)
            # All callbacks are still gated, so the default five-second wait expires.
            fetch(shutdown_task)
            GC.gc(true)
            @test alive(first)
            @test HR._addrinfo_live_threads() == HR._ADDRINFO_POOL_SIZE

            second, second_arg = queue_reference()
            start_pool()
            wait_gate(second_arg, HR._ADDRINFO_POOL_SIZE)
            HR.shutdown!(0.01)
            GC.gc(true)
            @test alive(first) && alive(second)
            @test HR._addrinfo_live_threads() == 2 * HR._ADDRINFO_POOL_SIZE

            release_gate(first_arg)
            wait_gate(first_arg, HR._ADDRINFO_POOL_SIZE; completed=true)
            @test collect_queue(first) == :ok
            @test alive(second)
            @test HR._addrinfo_live_threads() == HR._ADDRINFO_POOL_SIZE
            release_gate(second_arg)
            wait_gate(second_arg, HR._ADDRINFO_POOL_SIZE; completed=true)
            @test collect_queue(second) == :ok
            @test HR._addrinfo_live_threads() == 0
        end

        @testset "resolver creation and detach failures" begin
            starts_before = native_starts[]
            spawn_failure[] = :create
            @test_throws SystemError start_pool()
            @test native_starts[] == starts_before
            @test HR._ADDRINFO_STARTED_THREADS[] == 0
            @test HR._addrinfo_live_threads() == 0
            @test isempty(HR._ADDRINFO_QUEUE_ROOTS)

            queue, arg = queue_reference()
            spawn_failure[] = :detach
            @test_throws SystemError start_pool()
            wait_gate(arg, 1)
            @test native_starts[] == starts_before + 1
            @test HR._ADDRINFO_STARTED_THREADS[] == 1
            @test HR._addrinfo_live_threads() == 1
            spawn_failure[] = :create
            @test_throws SystemError start_pool()
            @test native_starts[] == starts_before + 1
            @test HR._ADDRINFO_STARTED_THREADS[] == 1
            @test HR._addrinfo_live_threads() == 1
            HR.shutdown!(0.01)
            GC.gc(true)
            @test alive(queue)
            release_gate(arg)
            wait_gate(arg, 1; completed=true)
            @test collect_queue(queue) == :ok
            @test HR._addrinfo_live_threads() == 0
            @test isempty(HR._ADDRINFO_QUEUE_ROOTS)
        end

        @testset "poller creation and detach failures" begin
            starts_before = native_starts[]
            spawn_failure[] = :create
            @test_throws SystemError IP.init!()
            @test native_starts[] == starts_before
            @test IP.POLLER[].backend_state === nothing
            @test !(@atomic IP.POLLER[].running)

            IP._POLLER_THREAD_ENTRY_C[] = @cfunction(poller_gate, Ptr{Cvoid}, (Ptr{Cvoid},))
            spawn_failure[] = :detach
            startup = @async try
                IP.init!()
            catch ex
                ex
            end
            @test timedwait(() -> native_starts[] == starts_before + 1, 10.0) == :ok
            state = IP.POLLER[]
            arg = pointer_from_objref(state)
            wait_gate(arg, 1)
            @test !istaskdone(startup)
            @test state.backend_state !== nothing
            release_gate(arg)
            @test fetch(startup) isa SystemError
            wait_gate(arg, 1; completed=true)
            @test state.backend_state === nothing
            @test !(@atomic state.running)
        end
    finally
        HR._ADDRINFO_THREAD_ENTRY_C[] = resolver_entry
        IP._POLLER_THREAD_ENTRY_C[] = poller_entry
        spawn_failure[] = :none
        lock(gate_condition) do
            for gate in values(gates)
                gate.released = true
            end
            notify(gate_condition; all=true)
        end
        HR.shutdown!()
        IP.shutdown!()
        Base.delete_method(injected_method)
    end
    @test !isempty(HR._native_getaddrinfo("localhost"; flags=HR._AI_ALL | HR._AI_V4MAPPED))
    HR.shutdown!()
    @test HR._addrinfo_live_threads() == 0
    IP.init!()
    IP.shutdown!()
    @test IP.POLLER[].backend_state === nothing
end

end
