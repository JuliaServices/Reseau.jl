using Test
using Reseau
using Libdl

@testset "shared library load failure" begin
    res = Reseau.shared_library_load("not-a-real-library.blah")
    @test res isa Reseau.ErrorResult
    @test res.code == Reseau.ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE
end

@testset "shared library load/find" begin
    path = Libdl.dlpath("libjulia")
    if path === nothing || isempty(path)
        @test true
    else
        lib = Reseau.shared_library_load(path)
        @test !(lib isa Reseau.ErrorResult)
        lib isa Reseau.ErrorResult && return

        sym = Reseau.shared_library_find_symbol(lib, "jl_errno")
        @test !(sym isa Reseau.ErrorResult)
        sym isa Reseau.ErrorResult && return
        @test sym != C_NULL

        bad = Reseau.shared_library_find_symbol(lib, "not_a_real_function")
        @test bad isa Reseau.ErrorResult

        Reseau.shared_library_unload!(lib)
    end
end

@testset "shared library load default" begin
    lib = Reseau.shared_library_load_default()
    @test !(lib isa Reseau.ErrorResult)
    lib isa Reseau.ErrorResult && return
    Reseau.shared_library_unload!(lib)
end
