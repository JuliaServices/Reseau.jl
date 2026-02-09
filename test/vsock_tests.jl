using Test
using Reseau
import Reseau: Sockets

@testset "vsock parse" begin
    @static if Sys.islinux()
        cid = Sockets._parse_vsock_cid("3")
        @test cid == UInt32(3)

        cid_any = Sockets._parse_vsock_cid("-1")
        @test cid_any == Sockets.VMADDR_CID_ANY

        @test Sockets._parse_vsock_cid("not-a-number") isa Reseau.ErrorResult
        @test Sockets._parse_vsock_cid("-2") isa Reseau.ErrorResult
        @test Sockets._parse_vsock_cid(string(typemax(UInt32) + 1)) isa Reseau.ErrorResult
    else
        @test true
    end
end
