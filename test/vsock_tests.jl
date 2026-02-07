using Test
using Reseau

@testset "vsock parse" begin
    @static if Sys.islinux()
        cid = Reseau._parse_vsock_cid("3")
        @test cid == UInt32(3)

        cid_any = Reseau._parse_vsock_cid("-1")
        @test cid_any == Reseau.VMADDR_CID_ANY

        @test Reseau._parse_vsock_cid("not-a-number") isa Reseau.ErrorResult
        @test Reseau._parse_vsock_cid("-2") isa Reseau.ErrorResult
        @test Reseau._parse_vsock_cid(string(typemax(UInt32) + 1)) isa Reseau.ErrorResult
    else
        @test true
    end
end
