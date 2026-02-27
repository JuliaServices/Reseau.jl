@enumx LogLevel::UInt8 begin
    NONE = 0
    FATAL = 1
    ERROR = 2
    WARN = 3
    INFO = 4
    DEBUG = 5
    TRACE = 6
end

const LOG_LEVEL_NONE = LogLevel.NONE
const LOG_LEVEL_FATAL = LogLevel.FATAL
const LOG_LEVEL_ERROR = LogLevel.ERROR
const LOG_LEVEL_WARN = LogLevel.WARN
const LOG_LEVEL_INFO = LogLevel.INFO
const LOG_LEVEL_DEBUG = LogLevel.DEBUG
const LOG_LEVEL_TRACE = LogLevel.TRACE

const LogSubject = UInt32

const LOG_SUBJECT_STRIDE_BITS = 10
const LOG_SUBJECT_STRIDE = UInt32(1) << LOG_SUBJECT_STRIDE_BITS

LOG_SUBJECT_BEGIN_RANGE(x) = LogSubject(x) * LOG_SUBJECT_STRIDE
LOG_SUBJECT_END_RANGE(x) = (LogSubject(x) + 1) * LOG_SUBJECT_STRIDE - 1

struct LogSubjectInfo
    subject_id::LogSubject
    subject_name::String
    subject_description::String
end

const LS_COMMON_GENERAL = LOG_SUBJECT_BEGIN_RANGE(COMMON_PACKAGE_ID)
const LS_COMMON_TASK_SCHEDULER = LS_COMMON_GENERAL + 1
const LS_COMMON_THREAD = LS_COMMON_GENERAL + 2
const LS_COMMON_MEMTRACE = LS_COMMON_GENERAL + 3
const LS_COMMON_XML_PARSER = LS_COMMON_GENERAL + 4
const LS_COMMON_IO = LS_COMMON_GENERAL + 5
const LS_COMMON_BUS = LS_COMMON_GENERAL + 6
const LS_COMMON_TEST = LS_COMMON_GENERAL + 7
const LS_COMMON_JSON_PARSER = LS_COMMON_GENERAL + 8
const LS_COMMON_CBOR = LS_COMMON_GENERAL + 9
const LS_COMMON_LAST = LOG_SUBJECT_END_RANGE(COMMON_PACKAGE_ID)

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

import Dates

abstract type AbstractLogFormatter end

@enumx DateFormat::UInt8 begin
    RFC822 = 0
    ISO_8601 = 1
    ISO_8601_BASIC = 2
    AUTO_DETECT = 3
end

const date_format = DateFormat.T

struct StandardLogFormatter <: AbstractLogFormatter
    date_format::date_format
end

const _LOG_LEVEL_LABELS = (
    "NONE",
    "FATAL",
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG",
    "TRACE",
)

@inline function _log_level_label(level::LogLevel.T)
    idx = Int(level) + 1
    return 1 <= idx <= length(_LOG_LEVEL_LABELS) ? _LOG_LEVEL_LABELS[idx] : "UNKNOWN"
end

const _TS_FMT_ISO_8601_UTC = Dates.DateFormat("yyyy-mm-dd\\THH:MM:SS")
const _TS_FMT_ISO_8601_BASIC_UTC = Dates.DateFormat("yyyymmdd\\THHMMSS")

function _timestamp_string(fmt::date_format)
    dt = Dates.now(Dates.UTC)
    if fmt == DateFormat.RFC822
        return Dates.format(dt, Dates.RFC1123Format) * " GMT"
    elseif fmt == DateFormat.ISO_8601_BASIC
        return Dates.format(dt, _TS_FMT_ISO_8601_BASIC_UTC) * "Z"
    else
        return Dates.format(dt, _TS_FMT_ISO_8601_UTC) * "Z"
    end
end

function format_line(formatter::StandardLogFormatter, level::LogLevel.T, subject::LogSubject, msg::AbstractString)
    timestamp = _timestamp_string(formatter.date_format)
    level_str = _log_level_label(level)
    subject_name = log_subject_name(subject)
    subject_segment = subject_name == "" ? "" : string("[", subject_name, "] ")
    thread_id = string(Threads.threadid())
    return string("[", level_str, "] [", timestamp, "] [", thread_id, "] ", subject_segment, "- ", msg, "\n")
end

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

@inline function logf(level::LogLevel.T, subject::LogSubject, msg::Function)
    Int(level) > Int(STATIC_LOG_LEVEL) && return nothing
    return logf(level, subject, msg())
end

@inline function logf(level::Cint, subject::LogSubject, msg::AbstractString)
    return logf(_level_from_int(level), subject, msg)
end

@inline function logf(level::Cint, subject::LogSubject, msg::Function)
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
