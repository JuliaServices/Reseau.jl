mutable struct LoggerPipeline{F <: AbstractLogFormatter, C <: AbstractLogChannel, W <: AbstractLogWriter}
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

@inline function log!(logger::LoggerPipeline, level::LogLevel.T, subject::LogSubject, fmt::AbstractString)
    if Int(level) > Int(log_level(logger, subject))
        return nothing
    end
    line = format_line(logger.formatter, level, subject, fmt)
    send!(logger.channel, logger.writer, line)
    return nothing
end

function close!(logger::LoggerPipeline)
    close!(logger.channel)
    close!(logger.writer)
    return nothing
end

const _DEFAULT_LOGGER = LoggerPipeline(
    StandardLogFormatter(DateFormat.ISO_8601),
    ForegroundChannel(),
    log_writer_stdout(),
    LOG_LEVEL_NONE,
)
const DefaultLoggerPipeline = typeof(_DEFAULT_LOGGER)
const CURRENT_LOGGER = ScopedValue{DefaultLoggerPipeline}(_DEFAULT_LOGGER)

@inline function current_logger()
    return CURRENT_LOGGER[]
end

@inline function logger_get()
    return current_logger()
end

@inline function logger_set(logger::LoggerPipeline)
    throw(ArgumentError("global logger mutation is not supported; use with_logger(logger) do ... end"))
end

@inline function with_logger(f, logger::DefaultLoggerPipeline)
    return with(f, CURRENT_LOGGER => logger)
end

@inline function with_logger(logger::LoggerPipeline, f)
    logger isa DefaultLoggerPipeline || throw(ArgumentError("with_logger only supports the default logger pipeline type"))
    return with_logger(f, logger)
end

@inline function _level_from_int(level::Integer)
    return LogLevel.T(Int(level))
end

const STATIC_LOG_LEVEL = LOG_LEVEL_INFO

@inline function logf(level::Integer, subject::Integer, msg::AbstractString)
    return logf(_level_from_int(level), LogSubject(subject), msg)
end

@inline function logf(level::LogLevel.T, subject::Integer, msg::AbstractString)
    return logf(level, LogSubject(subject), msg)
end

@inline function logf(level::Integer, subject::LogSubject, msg::AbstractString)
    return logf(_level_from_int(level), subject, msg)
end

@inline function logf(level::LogLevel.T, subject::LogSubject, msg::AbstractString)
    Int(level) > Int(STATIC_LOG_LEVEL) && return nothing
    return log!(current_logger(), level, subject, msg)
end

@inline function logf(level::Cint, subject::LogSubject, msg::AbstractString)
    return logf(_level_from_int(level), subject, msg)
end

macro LOGF(level, subject, msg)
    return :(Int($level) > Int(STATIC_LOG_LEVEL) ? nothing : logf($level, $subject, $msg))
end

macro LOGF_FATAL(subject, msg)
    if Int(LOG_LEVEL_FATAL) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_FATAL, $subject, $msg))
end

macro LOGF_ERROR(subject, msg)
    if Int(LOG_LEVEL_ERROR) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_ERROR, $subject, $msg))
end

macro LOGF_WARN(subject, msg)
    if Int(LOG_LEVEL_WARN) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_WARN, $subject, $msg))
end

macro LOGF_INFO(subject, msg)
    if Int(LOG_LEVEL_INFO) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_INFO, $subject, $msg))
end

macro LOGF_DEBUG(subject, msg)
    if Int(LOG_LEVEL_DEBUG) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_DEBUG, $subject, $msg))
end

macro LOGF_TRACE(subject, msg)
    if Int(LOG_LEVEL_TRACE) > Int(STATIC_LOG_LEVEL)
        return :(nothing)
    end
    return :(logf(LOG_LEVEL_TRACE, $subject, $msg))
end

const _log_subject_registry = Dict{LogSubject, LogSubjectInfo}()

const _common_log_subject_infos = (
    LogSubjectInfo(LS_COMMON_GENERAL, "aws-c-common", "Subject for aws-c-common logging that doesn't belong to any particular category"),
    LogSubjectInfo(LS_COMMON_TASK_SCHEDULER, "task-scheduler", "Subject for task scheduler or task specific logging."),
    LogSubjectInfo(LS_COMMON_THREAD, "thread", "Subject for logging thread related functions."),
    LogSubjectInfo(LS_COMMON_MEMTRACE, "memtrace", "Output from the mem_trace_dump function"),
    LogSubjectInfo(LS_COMMON_XML_PARSER, "xml-parser", "Subject for xml parser specific logging."),
    LogSubjectInfo(LS_COMMON_IO, "common-io", "Common IO utilities"),
    LogSubjectInfo(LS_COMMON_BUS, "bus", "Message bus"),
    LogSubjectInfo(LS_COMMON_TEST, "test", "Unit/integration testing"),
    LogSubjectInfo(LS_COMMON_JSON_PARSER, "json-parser", "Subject for json parser specific logging"),
    LogSubjectInfo(LS_COMMON_CBOR, "cbor", "Subject for CBOR encode and decode"),
)

# Register common log subjects at module load time
for info in _common_log_subject_infos
    _log_subject_registry[info.subject_id] = info
end

function log_subject_name(subject::LogSubject)
    info = get(_log_subject_registry, subject, nothing)
    return info === nothing ? "" : info.subject_name
end

function log_subject_description(subject::LogSubject)
    info = get(_log_subject_registry, subject, nothing)
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
