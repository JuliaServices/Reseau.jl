using Test
using Reseau
using Libdl
import Reseau: EventLoops, Sockets

@testset "shared library load failure" begin
    @test_throws Reseau.ReseauError Sockets.shared_library_load("not-a-real-library.blah")
end

@testset "shared library load/find" begin
    path = Libdl.dlpath("libjulia")
    if path === nothing || isempty(path)
        @test true
    else
        lib = Sockets.shared_library_load(path)

        sym = Sockets.shared_library_find_symbol(lib, "jl_errno")
        @test sym != C_NULL

        @test_throws Reseau.ReseauError Sockets.shared_library_find_symbol(lib, "not_a_real_function")

        Sockets.shared_library_unload!(lib)
    end
end

@testset "shared library load default" begin
    lib = Sockets.shared_library_load_default()
    Sockets.shared_library_unload!(lib)
end
