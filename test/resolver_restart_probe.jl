using Reseau
get(ENV, "PROBE_DISABLE_GC", "false") == "true" && GC.enable(false)
const ND = Reseau.HostResolvers
function mark(msg)
    println(msg)
    flush(stdout)
end
begin
    for i in 1:100
        mark("iteration $i: resolve start")
        isempty(ND.resolve_tcp_addrs("tcp", "localhost:0")) && error("empty resolution")
        mark("iteration $i: resolve complete, shutdown start")
        ND.shutdown!()
        mark("iteration $i: shutdown complete")
        live = ND._addrinfo_live_threads()
        mark("iteration $i: live workers = $live, GC start")
        if get(ENV, "PROBE_DISABLE_GC", "false") != "true"
            GC.gc()
        end
        live == 0 || error("workers did not stop: $live")
        mark("iteration $i: GC complete")
    end
end
