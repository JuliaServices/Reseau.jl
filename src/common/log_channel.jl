abstract type AbstractLogChannel end

struct ForegroundChannel <: AbstractLogChannel end

mutable struct BackgroundChannel{W <: AbstractLogWriter} <: AbstractLogChannel
    queue::Channel{Tuple{W, String}}
    task::Task
end

function BackgroundChannel(::Type{W}; capacity::Integer = 256) where {W <: AbstractLogWriter}
    queue = Channel{Tuple{W, String}}(capacity)
    task = @async begin
        for (writer, line) in queue
            write!(writer, line)
        end
    end
    return BackgroundChannel{W}(queue, task)
end

@inline function send!(::ForegroundChannel, writer::AbstractLogWriter, line::AbstractString)
    write!(writer, line)
    return nothing
end

@inline function send!(channel::BackgroundChannel{W}, writer::W, line::AbstractString) where {W <: AbstractLogWriter}
    put!(channel.queue, (writer, String(line)))
    return nothing
end

@inline function close!(::ForegroundChannel)
    return nothing
end

function close!(channel::BackgroundChannel)
    close(channel.queue)
    wait(channel.task)
    return nothing
end
