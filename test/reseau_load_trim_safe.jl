const _TRIM_DEBUG = get(ENV, "RESEAU_TRIM_DEBUG", "0") == "1"

function _trim_debug(msg::AbstractString)::Nothing
    _TRIM_DEBUG || return nothing
    bytes = Vector{UInt8}(codeunits("[reseau-load-trim] " * String(msg) * "\n"))
    @static if Sys.iswindows()
        handle = ccall((:GetStdHandle, "kernel32"), Ptr{Cvoid}, (Int32,), Int32(-11))
        written = Ref{UInt32}(0)
        GC.@preserve bytes written begin
            _ = ccall(
                (:WriteFile, "kernel32"),
                Int32,
                (Ptr{Cvoid}, Ptr{UInt8}, UInt32, Ref{UInt32}, Ptr{Cvoid}),
                handle,
                pointer(bytes),
                UInt32(length(bytes)),
                written,
                C_NULL,
            )
        end
    else
        GC.@preserve bytes begin
            _ = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), Cint(1), pointer(bytes), Csize_t(length(bytes)))
        end
    end
    return nothing
end

using Reseau

function @main(args::Vector{String})::Cint
    _ = args
    _trim_debug("main start")
    _trim_debug("main return")
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
