using Test
using Reseau
using Libdl
import Reseau: EventLoops, Sockets

@testset "shared library load failure" begin
    res = Sockets.shared_library_load("not-a-real-library.blah")
    @test res isa Reseau.ErrorResult
    @test res.code == EventLoops.ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE
end

@testset "shared library load/find" begin
    path = Libdl.dlpath("libjulia")
    if path === nothing || isempty(path)
        @test true
    else
        lib = Sockets.shared_library_load(path)
        @test !(lib isa Reseau.ErrorResult)
        lib isa Reseau.ErrorResult && return

        sym = Sockets.shared_library_find_symbol(lib, "jl_errno")
        @test !(sym isa Reseau.ErrorResult)
        sym isa Reseau.ErrorResult && return
        @test sym != C_NULL

        bad = Sockets.shared_library_find_symbol(lib, "not_a_real_function")
        @test bad isa Reseau.ErrorResult

        Sockets.shared_library_unload!(lib)
    end
end

@testset "shared library load default" begin
    lib = Sockets.shared_library_load_default()
    @test !(lib isa Reseau.ErrorResult)
    lib isa Reseau.ErrorResult && return
    Sockets.shared_library_unload!(lib)
end
