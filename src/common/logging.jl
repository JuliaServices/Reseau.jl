abstract type AbstractLogger end

struct NullLogger <: AbstractLogger end

log_level(::NullLogger, ::LogSubject) = LOG_LEVEL_NONE
log!(::NullLogger, ::LogLevel.T, ::LogSubject, ::AbstractString, args...) = nothing
close!(::NullLogger) = nothing
set_log_level!(::NullLogger, ::LogLevel.T) = nothing

mutable struct LoggerPipeline{F <: AbstractLogFormatter, C <: AbstractLogChannel, W <: AbstractLogWriter} <: AbstractLogger
    formatter::F
    channel::C
    writer::W
    @atomic level::Int
end

function LoggerPipeline(formatter::F, channel::C, writer::W, level::LogLevel.T = LOG_LEVEL_INFO) where {F <: AbstractLogFormatter, C <: AbstractLogChannel, W <: AbstractLogWriter}
    return LoggerPipeline{F, C, W}(formatter, channel, writer, Int(level))
end

log_level(logger::LoggerPipeline, ::LogSubject) = LogLevel.T(@atomic logger.level)

function set_log_level!(logger::LoggerPipeline, level::LogLevel.T)
    @atomic logger.level = Int(level)
    return nothing
end

function log!(logger::LoggerPipeline, level::LogLevel.T, subject::LogSubject, fmt::AbstractString, args...)
    if Int(level) > Int(log_level(logger, subject))
        return nothing
    end
    line = format_line(logger.formatter, level, subject, fmt, args...)
    send!(logger.channel, logger.writer, line)
    return nothing
end

function close!(logger::LoggerPipeline)
    close!(logger.channel)
    close!(logger.writer)
    return nothing
end

const _default_logger = Ref{AbstractLogger}(NullLogger())
const _logger_override = ScopedValue{Union{AbstractLogger, Nothing}}(nothing)

@inline function current_logger()
    override = _logger_override[]
    return override === nothing ? _default_logger[] : override
end

@inline function logger_get()
    return current_logger()
end

@inline function logger_set(logger::AbstractLogger)
    _default_logger[] = logger
    return nothing
end

@inline function with_logger(logger::AbstractLogger, f::Function)
    return with(f, _logger_override => logger)
end

@inline function _level_from_int(level::Integer)
    return LogLevel.T(Int(level))
end

function logf(level::Integer, subject::Integer, fmt::AbstractString, args...)
    return logf(_level_from_int(level), LogSubject(subject), fmt, args...)
end

function logf(level::LogLevel.T, subject::Integer, fmt::AbstractString, args...)
    return logf(level, LogSubject(subject), fmt, args...)
end

function logf(level::Integer, subject::LogSubject, fmt::AbstractString, args...)
    return logf(_level_from_int(level), subject, fmt, args...)
end

function logf(level::LogLevel.T, subject::LogSubject, fmt::AbstractString, args...)
    return log!(current_logger(), level, subject, fmt, args...)
end

function logf(level::Cint, subject::LogSubject, fmt::AbstractString, args...)
    return logf(_level_from_int(level), subject, fmt, args...)
end

const STATIC_LOG_LEVEL = LOG_LEVEL_INFO

macro LOGF(level, subject, msg, args...)
    return :(Int($level) > Int(STATIC_LOG_LEVEL) ? nothing : logf($level, $subject, $msg, $(args...)))
end

macro LOGF_FATAL(subject, msg, args...)
    if Int(LOG_LEVEL_FATAL) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_FATAL, $subject, $msg, $(args...)))
end

macro LOGF_ERROR(subject, msg, args...)
    if Int(LOG_LEVEL_ERROR) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_ERROR, $subject, $msg, $(args...)))
end

macro LOGF_WARN(subject, msg, args...)
    if Int(LOG_LEVEL_WARN) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_WARN, $subject, $msg, $(args...)))
end

macro LOGF_INFO(subject, msg, args...)
    if Int(LOG_LEVEL_INFO) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_INFO, $subject, $msg, $(args...)))
end

macro LOGF_DEBUG(subject, msg, args...)
    if Int(LOG_LEVEL_DEBUG) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_DEBUG, $subject, $msg, $(args...)))
end

macro LOGF_TRACE(subject, msg, args...)
    if Int(LOG_LEVEL_TRACE) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_TRACE, $subject, $msg, $(args...)))
end

const _log_subject_registry = SmallRegistry{LogSubject, LogSubjectInfo}()

function log_subject_name(subject::LogSubject)
    info = registry_get(_log_subject_registry, subject, nothing)
    return info === nothing ? "" : info.subject_name
end

function log_subject_description(subject::LogSubject)
    info = registry_get(_log_subject_registry, subject, nothing)
    return info === nothing ? "" : info.subject_description
end

@inline function standard_logger(;
        level::LogLevel.T = LOG_LEVEL_INFO, writer::AbstractLogWriter = log_writer_stdout(),
        channel::AbstractLogChannel = ForegroundChannel(),
        date_format::date_format = DateFormat.ISO_8601
    )
    formatter = StandardLogFormatter(date_format)
    return LoggerPipeline(formatter, channel, writer, level)
end
