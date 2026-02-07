abstract type AbstractLogWriter end

struct FileLogWriter{I <: IO} <: AbstractLogWriter
    io::I
    close_on_cleanup::Bool
end

struct CFileLogWriter <: AbstractLogWriter
    file::Libc.FILE
end

@inline function write!(writer::FileLogWriter, line::AbstractString)
    print(writer.io, line)
    flush(writer.io)
    return nothing
end

@inline function close!(writer::FileLogWriter)
    writer.close_on_cleanup || return nothing
    close(writer.io)
    return nothing
end

@inline function write!(writer::CFileLogWriter, line::AbstractString)
    bytes = codeunits(line)
    wrote = GC.@preserve bytes writer begin
        ccall(
            :fwrite,
            Csize_t,
            (Ptr{Cvoid}, Csize_t, Csize_t, Ptr{Cvoid}),
            pointer(bytes),
            1,
            length(bytes),
            writer.file.ptr,
        )
    end
    if wrote == length(bytes)
        _ = ccall(:fflush, Cint, (Ptr{Cvoid},), writer.file.ptr)
    end
    return nothing
end

@inline function close!(writer::CFileLogWriter)
    close(writer.file)
    return nothing
end

@inline function log_writer_stdout()
    return FileLogWriter(stdout, false)
end

@inline function log_writer_stderr()
    return FileLogWriter(stderr, false)
end

function log_writer_file(path::AbstractString)
    file_ptr = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path, "ab")
    file_ptr == C_NULL && throw(ErrorException("failed to open log file: $(path)"))
    file = Libc.FILE(file_ptr)
    return CFileLogWriter(file)
end

@inline function log_writer_file(io::IO; close_on_cleanup::Bool = false)
    return FileLogWriter(io, close_on_cleanup)
end
