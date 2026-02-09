using Printf
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

@inline function _format_user_content(fmt::AbstractString, args::Tuple)
    isempty(args) && return fmt
    return Printf.format(Printf.Format(fmt), args...)
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
        # Treat AUTO_DETECT as ISO_8601 for logging.
        return Dates.format(dt, _TS_FMT_ISO_8601_UTC) * "Z"
    end
end

function format_line(formatter::StandardLogFormatter, level::LogLevel.T, subject::LogSubject, fmt::AbstractString, args...)
    user_content = _format_user_content(fmt, args)
    timestamp = _timestamp_string(formatter.date_format)
    level_str = _log_level_label(level)
    subject_name = log_subject_name(subject)
    subject_segment = subject_name == "" ? "" : string("[", subject_name, "] ")
    thread_id = string(Threads.threadid())
    return string("[", level_str, "] [", timestamp, "] [", thread_id, "] ", subject_segment, "- ", user_content, "\n")
end
