abstract type AbstractLogWriter end

struct FileLogWriter{I <: IO} <: AbstractLogWriter
    io::I
    close_on_cleanup::Bool
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

@inline function log_writer_stdout()
    return FileLogWriter(stdout, false)
end

@inline function log_writer_stderr()
    return FileLogWriter(stderr, false)
end

function log_writer_file(path::AbstractString)
    io = open(path, "a+")
    return FileLogWriter(io, true)
end

@inline function log_writer_file(io::IO; close_on_cleanup::Bool = false)
    return FileLogWriter(io, close_on_cleanup)
end
