using Test

@testset "test synchronization does not depend on wall-clock timing" begin
    # Qualified calls into Reseau's own timing API (e.g. `IP.sleep`,
    # `IP.timedwait`) are the product under test and stay allowed; the bans
    # target test-owned scheduling through Base.
    forbidden = [
        r"(?<![\w.])sleep\s*\(" => "sleep-based coordination",
        r"\bBase\.sleep\s*\(" => "sleep-based coordination",
        r"\bLibc\.systemsleep\s*\(" => "sleep-based coordination",
        r"(?<![\w.])timedwait\s*\(" => "deadline polling",
        r"\bBase\.timedwait\s*\(" => "deadline polling",
        r"(?<![\w.])time_ns\s*\(" => "monotonic-clock reads",
        r"\bBase\.time_ns\s*\(" => "monotonic-clock reads",
        r"(?<![\w.])time\s*\(\s*\)" => "wall-clock reads",
        r"@elapsed\b" => "elapsed-time assertions",
        r"(?<![\w.])Timer\s*\(" => "timer-based coordination",
        r"\bpollint\s*=" => "polling intervals",
        r"\btimeout_s\s*=" => "test-helper timeouts",
    ]
    # Exemptions (see test/README.md):
    # - timing_semantics_tests.jl is the one file allowed to read the clock;
    #   it holds the pause-safe lower-bound latency tests for the product's
    #   own timing primitives.
    # - The native TLS files read UNIX wall-clock seconds as protocol data
    #   (session-ticket created_at/use_by timestamps). Their tolerances are
    #   hours to days, so no runner pause can flip them.
    exemptions = Dict(
        "timing_semantics_tests.jl" => nothing, # all patterns allowed
        "tls_native_tls12_tests.jl" => [r"(?<![\w.])time\s*\(\s*\)"],
        "tls_native_tls13_tests.jl" => [r"(?<![\w.])time\s*\(\s*\)"],
    )
    policy_file = abspath(@__FILE__)
    for path in sort(filter(path -> endswith(path, ".jl"), readdir(@__DIR__; join=true)))
        abspath(path) == policy_file && continue
        name = basename(path)
        allowed = get(exemptions, name, missing)
        allowed === nothing && continue
        source = read(path, String)
        for (pattern, description) in forbidden
            allowed !== missing && any(a -> a.pattern == pattern.pattern, allowed) && continue
            occursin(pattern, source) && error("$(name) uses forbidden $(description)")
        end
    end
    @test true
end
