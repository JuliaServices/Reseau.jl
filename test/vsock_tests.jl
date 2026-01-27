using Test
using AwsIO

@testset "vsock parse" begin
    @static if Sys.islinux()
        cid = AwsIO._parse_vsock_cid("3")
        @test cid == UInt32(3)

        cid_any = AwsIO._parse_vsock_cid("-1")
        @test cid_any == AwsIO.VMADDR_CID_ANY

        @test AwsIO._parse_vsock_cid("not-a-number") isa AwsIO.ErrorResult
        @test AwsIO._parse_vsock_cid("-2") isa AwsIO.ErrorResult
        @test AwsIO._parse_vsock_cid(string(typemax(UInt32) + 1)) isa AwsIO.ErrorResult
    else
        @test true
    end
end
