using Test
using AwsIO
using Libdl

@testset "shared library load failure" begin
    res = AwsIO.shared_library_load("not-a-real-library.blah")
    @test res isa AwsIO.ErrorResult
    @test res.code == AwsIO.ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE
end

@testset "shared library load/find" begin
    path = Libdl.dlpath("libjulia")
    if path === nothing || isempty(path)
        @test true
    else
        lib = AwsIO.shared_library_load(path)
        @test !(lib isa AwsIO.ErrorResult)
        lib isa AwsIO.ErrorResult && return

        sym = AwsIO.shared_library_find_symbol(lib, "jl_errno")
        @test !(sym isa AwsIO.ErrorResult)
        sym isa AwsIO.ErrorResult && return
        @test sym != C_NULL

        bad = AwsIO.shared_library_find_symbol(lib, "not_a_real_function")
        @test bad isa AwsIO.ErrorResult

        AwsIO.shared_library_unload!(lib)
    end
end

@testset "shared library load default" begin
    lib = AwsIO.shared_library_load_default()
    @test !(lib isa AwsIO.ErrorResult)
    lib isa AwsIO.ErrorResult && return
    AwsIO.shared_library_unload!(lib)
end
