using Libdl

const _deps_dir = @__DIR__
const _src_dir = joinpath(_deps_dir, "src")
const _lib_dir = joinpath(_deps_dir, "usr", "lib")
const _lib_name = "libawsio_nw_shim"
const _deps_file = joinpath(_deps_dir, "deps.jl")

function _write_deps(libpath::AbstractString)
    open(_deps_file, "w") do io
        println(io, "const libawsio_nw_shim = \"", libpath, "\"")
    end
    return nothing
end

if Sys.isapple()
    mkpath(_lib_dir)
    src = joinpath(_src_dir, "awsio_nw_shim.c")
    libpath = joinpath(_lib_dir, _lib_name * "." * Libdl.dlext)
    cc = get(ENV, "CC", "cc")
    cmd = `$(cc) -fPIC -shared -fblocks -o $(libpath) $(src) -framework Network -framework Security -framework CoreFoundation`
    run(cmd)
    _write_deps(libpath)
else
    _write_deps("")
end
