using Printf

abstract type AbstractLogFormatter end

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

function _timestamp_string(date_format::date_format)
    buf = Vector{UInt8}(undef, DATE_TIME_STR_MAX_LEN)
    byte_buf = Ref(byte_buf_from_empty_array(buf))
    dt = Ref{date_time}()
    date_time_init_now(dt)
    if date_time_to_utc_time_str(dt, date_format, byte_buf) != OP_SUCCESS
        return ""
    end
    return String(buf[1:byte_buf[].len])
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
