using Test
using Reseau
import Reseau: Sockets

@testset "vsock parse" begin
    @static if Sys.islinux()
        cid = Sockets._parse_vsock_cid("3")
        @test cid == UInt32(3)

        cid_any = Sockets._parse_vsock_cid("-1")
        @test cid_any == Sockets.VMADDR_CID_ANY

        @test_throws Reseau.ReseauError Sockets._parse_vsock_cid("not-a-number")
        @test_throws Reseau.ReseauError Sockets._parse_vsock_cid("-2")
        @test_throws Reseau.ReseauError Sockets._parse_vsock_cid(string(typemax(UInt32) + 1))
    else
        @test true
    end
end
