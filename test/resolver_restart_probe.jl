using Reseau, Test
const ND = Reseau.HostResolvers
function mark(msg)
    println(msg)
    flush(stdout)
end
@testset "Resolver restart probe" begin
    for i in 1:100
        mark("iteration $i: resolve start")
        @test !isempty(ND.resolve_tcp_addrs("tcp", "localhost:0"))
        mark("iteration $i: resolve complete, shutdown start")
        ND.shutdown!()
        mark("iteration $i: shutdown complete")
        @test ND._addrinfo_live_threads() == 0
        GC.gc()
        mark("iteration $i: GC complete")
    end
end
