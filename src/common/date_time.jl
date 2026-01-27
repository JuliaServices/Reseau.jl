const DATE_TIME_STR_MAX_LEN = 100
const DATE_TIME_STR_MAX_BASIC_LEN = 20

@enumx DateFormat::UInt8 begin
    RFC822 = 0
    ISO_8601 = 1
    ISO_8601_BASIC = 2
    AUTO_DETECT = 3
end

@enumx DateMonth::UInt8 begin
    JANUARY = 0
    FEBRUARY = 1
    MARCH = 2
    APRIL = 3
    MAY = 4
    JUNE = 5
    JULY = 6
    AUGUST = 7
    SEPTEMBER = 8
    OCTOBER = 9
    NOVEMBER = 10
    DECEMBER = 11
end

@enumx DayOfWeek::UInt8 begin
    SUNDAY = 0
    MONDAY = 1
    TUESDAY = 2
    WEDNESDAY = 3
    THURSDAY = 4
    FRIDAY = 5
    SATURDAY = 6
end

const date_format = DateFormat.T
const date_month = DateMonth.T
const day_of_week = DayOfWeek.T

struct date_time
    timestamp::time_t
    milliseconds::UInt16
    tz::NTuple{6, UInt8}
    gmt_time::tm
    local_time::tm
    utc_assumed::UInt8
end

const _RFC822_DATE_FORMAT_STR_MINUS_Z = "%%a, %%d %%b %%Y %%H:%%M:%%S GMT"
const _RFC822_DATE_FORMAT_STR_WITH_Z = "%%a, %%d %%b %%Y %%H:%%M:%%S %%Z"
const _RFC822_SHORT_DATE_FORMAT_STR = "%%a, %%d %%b %%Y"
const _ISO_8601_LONG_DATE_FORMAT_STR = "%%Y-%%m-%%dT%%H:%%M:%%SZ"
const _ISO_8601_SHORT_DATE_FORMAT_STR = "%%Y-%%m-%%d"
const _ISO_8601_LONG_BASIC_DATE_FORMAT_STR = "%%Y%%m%%dT%%H%%M%%SZ"
const _ISO_8601_SHORT_BASIC_DATE_FORMAT_STR = "%%Y%%m%%d"

const _month_jan = Ref{UInt32}(0)
const _month_feb = Ref{UInt32}(0)
const _month_mar = Ref{UInt32}(0)
const _month_apr = Ref{UInt32}(0)
const _month_may = Ref{UInt32}(0)
const _month_jun = Ref{UInt32}(0)
const _month_jul = Ref{UInt32}(0)
const _month_aug = Ref{UInt32}(0)
const _month_sep = Ref{UInt32}(0)
const _month_oct = Ref{UInt32}(0)
const _month_nov = Ref{UInt32}(0)
const _month_dec = Ref{UInt32}(0)
const _tz_utc = Ref{UInt32}(0)
const _tz_gmt = Ref{UInt32}(0)

@inline function _tm_with(
        tm_val::tm;
        sec::Cint = tm_val.tm_sec,
        min::Cint = tm_val.tm_min,
        hour::Cint = tm_val.tm_hour,
        mday::Cint = tm_val.tm_mday,
        mon::Cint = tm_val.tm_mon,
        year::Cint = tm_val.tm_year,
        wday::Cint = tm_val.tm_wday,
        yday::Cint = tm_val.tm_yday,
        isdst::Cint = tm_val.tm_isdst,
    )
    @static if _PLATFORM_WINDOWS
        return tm(sec, min, hour, mday, mon, year, wday, yday, isdst)
    else
        return tm(sec, min, hour, mday, mon, year, wday, yday, isdst, tm_val.tm_gmtoff, tm_val.tm_zone)
    end
end

@inline function _triplet_to_index(ptr::Ptr{UInt8})
    return UInt32(_ascii_tolower(unsafe_load(ptr))) |
        (UInt32(_ascii_tolower(unsafe_load(ptr + 1))) << 8) |
        (UInt32(_ascii_tolower(unsafe_load(ptr + 2))) << 16)
end

function _check_init_str_to_int()
    if _month_jan[] == 0
        _month_jan[] = _triplet_to_index(pointer(codeunits("jan")))
        _month_feb[] = _triplet_to_index(pointer(codeunits("feb")))
        _month_mar[] = _triplet_to_index(pointer(codeunits("mar")))
        _month_apr[] = _triplet_to_index(pointer(codeunits("apr")))
        _month_may[] = _triplet_to_index(pointer(codeunits("may")))
        _month_jun[] = _triplet_to_index(pointer(codeunits("jun")))
        _month_jul[] = _triplet_to_index(pointer(codeunits("jul")))
        _month_aug[] = _triplet_to_index(pointer(codeunits("aug")))
        _month_sep[] = _triplet_to_index(pointer(codeunits("sep")))
        _month_oct[] = _triplet_to_index(pointer(codeunits("oct")))
        _month_nov[] = _triplet_to_index(pointer(codeunits("nov")))
        _month_dec[] = _triplet_to_index(pointer(codeunits("dec")))
        _tz_utc[] = _triplet_to_index(pointer(codeunits("utc")))
        _tz_gmt[] = _triplet_to_index(pointer(codeunits("gmt")))
    end
    return nothing
end

function _get_month_number_from_str(time_string::Ptr{UInt8}, start_index::Integer, stop_index::Integer)
    _check_init_str_to_int()
    if stop_index - start_index < 3
        return -1
    end
    comp_val = _triplet_to_index(time_string + start_index)
    if _month_jan[] == comp_val
        return 0
    elseif _month_feb[] == comp_val
        return 1
    elseif _month_mar[] == comp_val
        return 2
    elseif _month_apr[] == comp_val
        return 3
    elseif _month_may[] == comp_val
        return 4
    elseif _month_jun[] == comp_val
        return 5
    elseif _month_jul[] == comp_val
        return 6
    elseif _month_aug[] == comp_val
        return 7
    elseif _month_sep[] == comp_val
        return 8
    elseif _month_oct[] == comp_val
        return 9
    elseif _month_nov[] == comp_val
        return 10
    elseif _month_dec[] == comp_val
        return 11
    end
    return -1
end

function _is_utc_time_zone(tz_ptr::Ptr{UInt8})
    _check_init_str_to_int()
    len = 0
    while unsafe_load(tz_ptr + len) != 0x00
        len += 1
    end
    if len > 0
        first = _ascii_tolower(unsafe_load(tz_ptr))
        if first == UInt8('z')
            return true
        end
        if len == 5
            sign = unsafe_load(tz_ptr)
            if sign == UInt8('+') || sign == UInt8('-')
                return true
            end
        end
        if len == 2
            return _ascii_tolower(unsafe_load(tz_ptr)) == UInt8('u') &&
                _ascii_tolower(unsafe_load(tz_ptr + 1)) == UInt8('t')
        end
        if len < 3
            return false
        end
        comp_val = _triplet_to_index(tz_ptr)
        if comp_val == _tz_utc[] || comp_val == _tz_gmt[]
            return true
        end
    end
    return false
end

function _get_time_struct(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time_ref = Ref{tm}()
    if local_time
        localtime(dt_val.timestamp, time_ref)
    else
        gmtime(dt_val.timestamp, time_ref)
    end
    return time_ref[]
end

const _STATE_ON_WEEKDAY = 0
const _STATE_ON_SPACE_DELIM = 1
const _STATE_ON_YEAR = 2
const _STATE_ON_MONTH = 3
const _STATE_ON_MONTH_DAY = 4
const _STATE_ON_HOUR = 5
const _STATE_ON_MINUTE = 6
const _STATE_ON_SECOND = 7
const _STATE_ON_TZ = 8

function _parse_rfc_822(
        date_str_cursor::Ptr{ByteCursor},
        parsed_time::Ptr{tm},
        tz_buf::Memory{UInt8},
        utc_assumed::Base.RefValue{Bool},
    )
    len = Int(unsafe_load(date_str_cursor).len)
    index = 0
    state_start_index = 0
    state = _STATE_ON_WEEKDAY
    error = false
    zero_struct!(parsed_time)
    fill!(tz_buf, 0x00)
    utc_assumed[] = false

    ptr = unsafe_load(date_str_cursor).ptr
    while !error && index < len
        c = unsafe_load(ptr + index)
        if state == _STATE_ON_WEEKDAY
            if c == UInt8(',')
                state = _STATE_ON_SPACE_DELIM
                state_start_index = index + 1
            elseif isdigit(c)
                state = _STATE_ON_MONTH_DAY
            elseif !isalpha(c)
                error = true
            end
        elseif state == _STATE_ON_SPACE_DELIM
            if is_space(c)
                state = _STATE_ON_MONTH_DAY
                state_start_index = index + 1
            else
                error = true
            end
        elseif state == _STATE_ON_MONTH_DAY
            if isdigit(c)
                tm_val = unsafe_load(parsed_time)
                val = tm_val.tm_mday * 10 + (c - UInt8('0'))
                unsafe_store!(parsed_time, _tm_with(tm_val; mday = Cint(val)))
            elseif is_space(c)
                state = _STATE_ON_MONTH
                state_start_index = index + 1
            else
                error = true
            end
        elseif state == _STATE_ON_MONTH
            if is_space(c)
                month_number = _get_month_number_from_str(ptr, state_start_index, index + 1)
                if month_number > -1
                    tm_val = unsafe_load(parsed_time)
                    unsafe_store!(parsed_time, _tm_with(tm_val; mon = Cint(month_number)))
                    state = _STATE_ON_YEAR
                    state_start_index = index + 1
                else
                    error = true
                end
            elseif !isalpha(c)
                error = true
            end
        elseif state == _STATE_ON_YEAR
            if is_space(c) && index - state_start_index == 4
                tm_val = unsafe_load(parsed_time)
                year = tm_val.tm_year - 1900
                unsafe_store!(parsed_time, _tm_with(tm_val; year = Cint(year)))
                state = _STATE_ON_HOUR
                state_start_index = index + 1
            elseif is_space(c) && index - state_start_index == 2
                tm_val = unsafe_load(parsed_time)
                year = tm_val.tm_year + (2000 - 1900)
                unsafe_store!(parsed_time, _tm_with(tm_val; year = Cint(year)))
                state = _STATE_ON_HOUR
                state_start_index = index + 1
            elseif isdigit(c)
                tm_val = unsafe_load(parsed_time)
                year = tm_val.tm_year * 10 + (c - UInt8('0'))
                unsafe_store!(parsed_time, _tm_with(tm_val; year = Cint(year)))
            else
                error = true
            end
        elseif state == _STATE_ON_HOUR
            if c == UInt8(':') && index - state_start_index == 2
                state = _STATE_ON_MINUTE
                state_start_index = index + 1
            elseif isdigit(c)
                tm_val = unsafe_load(parsed_time)
                hour = tm_val.tm_hour * 10 + (c - UInt8('0'))
                unsafe_store!(parsed_time, _tm_with(tm_val; hour = Cint(hour)))
            else
                error = true
            end
        elseif state == _STATE_ON_MINUTE
            if c == UInt8(':') && index - state_start_index == 2
                state = _STATE_ON_SECOND
                state_start_index = index + 1
            elseif isdigit(c)
                tm_val = unsafe_load(parsed_time)
                min = tm_val.tm_min * 10 + (c - UInt8('0'))
                unsafe_store!(parsed_time, _tm_with(tm_val; min = Cint(min)))
            else
                error = true
            end
        elseif state == _STATE_ON_SECOND
            if is_space(c) && index - state_start_index == 2
                state = _STATE_ON_TZ
                state_start_index = index + 1
            elseif isdigit(c)
                tm_val = unsafe_load(parsed_time)
                sec = tm_val.tm_sec * 10 + (c - UInt8('0'))
                unsafe_store!(parsed_time, _tm_with(tm_val; sec = Cint(sec)))
            else
                error = true
            end
        elseif state == _STATE_ON_TZ
            if (isalnum(c) || c == UInt8('-') || c == UInt8('+')) && (index - state_start_index) < 5
                tz_buf[index - state_start_index + 1] = c
            else
                error = true
            end
        else
            error = true
        end
        index += 1
    end

    if tz_buf[1] != 0x00
        GC.@preserve tz_buf begin
            if _is_utc_time_zone(pointer(tz_buf))
                utc_assumed[] = true
            else
                error = true
            end
        end
    end

    return !error && state == _STATE_ON_TZ
end

function _read_n_digits(str::Base.RefValue{ByteCursor}, n::Integer, out_val::Base.RefValue{Int})
    val = 0
    if str[].len < n
        return false
    end
    for i in 0:(n - 1)
        c = unsafe_load(str[].ptr + i)
        if isdigit(c)
            val = val * 10 + (c - UInt8('0'))
        else
            return false
        end
    end
    byte_cursor_advance(str, n)
    out_val[] = val
    return true
end

function _read_1_char(str::Base.RefValue{ByteCursor}, out_c::Base.RefValue{UInt8})
    if str[].len == 0
        return false
    end
    out_c[] = str[].ptr[1]
    byte_cursor_advance(str, 1)
    return true
end

function _advance_if_next_char_is(str::Base.RefValue{ByteCursor}, c::UInt8)
    if str[].len == 0 || str[].ptr[1] != c
        return false
    end
    byte_cursor_advance(str, 1)
    return true
end

function _skip_optional_fractional_seconds(str::Base.RefValue{ByteCursor})
    if str[].len == 0
        return true
    end
    c = str[].ptr[1]
    if c != UInt8('.') && c != UInt8(',')
        return true
    end
    num_digits = 0
    len = Int(str[].len)
    for i in 2:len
        if isdigit(str[].ptr[i])
            num_digits += 1
        else
            break
        end
    end
    if num_digits == 0
        return false
    end
    byte_cursor_advance(str, 1 + num_digits)
    return true
end

function _parse_iso_8601(str::ByteCursor, parsed_time::Ptr{tm}, seconds_offset::Base.RefValue{time_t})
    zero_struct!(parsed_time)
    seconds_offset[] = 0
    c = Ref{UInt8}(0)
    str_ref = Ref(str)

    year = Ref{Int}(0)
    if !_read_n_digits(str_ref, 4, year)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; year = Cint(year[] - 1900)))

    has_date_separator = _advance_if_next_char_is(str_ref, UInt8('-'))

    month = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, month)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; mon = Cint(month[] - 1)))

    if has_date_separator
        if !_read_1_char(str_ref, c) || c[] != UInt8('-')
            return false
        end
    end

    month_day = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, month_day)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; mday = Cint(month_day[])))

    if str_ref[].len == 0
        return true
    end

    if !_read_1_char(str_ref, c) || (_ascii_tolower(c[]) != UInt8('t') && c[] != UInt8(' '))
        return false
    end

    hour = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, hour)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; hour = Cint(hour[])))

    has_time_separator = _advance_if_next_char_is(str_ref, UInt8(':'))

    minute = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, minute)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; min = Cint(minute[])))

    if has_time_separator
        if !_read_1_char(str_ref, c) || c[] != UInt8(':')
            return false
        end
    end

    second = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, second)
        return false
    end
    tm_val = unsafe_load(parsed_time)
    unsafe_store!(parsed_time, _tm_with(tm_val; sec = Cint(second[])))

    if !_skip_optional_fractional_seconds(str_ref)
        return false
    end

    if !_read_1_char(str_ref, c)
        return false
    end

    if _ascii_tolower(c[]) == UInt8('z')
        return true
    end

    if c[] != UInt8('+') && c[] != UInt8('-')
        return false
    end

    negative_offset = c[] == UInt8('-')
    hours_offset = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, hours_offset)
        return false
    end
    _advance_if_next_char_is(str_ref, UInt8(':'))
    minutes_offset = Ref{Int}(0)
    if !_read_n_digits(str_ref, 2, minutes_offset)
        return false
    end

    seconds_offset[] = time_t(hours_offset[] * 3600 + minutes_offset[] * 60)
    if negative_offset
        seconds_offset[] = -seconds_offset[]
    end
    return true
end

function date_time_init_now(dt::Ptr{date_time})
    precondition(dt != C_NULL)
    current_time_ns = Ref{UInt64}(0)
    sys_clock_get_ticks(current_time_ns)
    date_time_init_epoch_millis(dt, timestamp_convert(current_time_ns[], TIMESTAMP_NANOS, TIMESTAMP_MILLIS, nothing))
    return nothing
end

function date_time_init_now(dt::Base.RefValue{date_time})
    return date_time_init_now(Base.unsafe_convert(Ptr{date_time}, dt))
end

function date_time_init_epoch_millis(dt::Ptr{date_time}, ms_since_epoch::UInt64)
    precondition(dt != C_NULL)
    remainder = Ref{UInt64}(0)
    timestamp = timestamp_convert(ms_since_epoch, TIMESTAMP_MILLIS, TIMESTAMP_SECS, remainder)
    millis = UInt16(remainder[])
    gmt_ref = Ref{tm}()
    local_ref = Ref{tm}()
    gmtime(time_t(timestamp), gmt_ref)
    localtime(time_t(timestamp), local_ref)
    dt_val = date_time(
        time_t(timestamp),
        millis,
        ntuple(_ -> UInt8(0), 6),
        gmt_ref[],
        local_ref[],
        UInt8(0),
    )
    unsafe_store!(dt, dt_val)
    return nothing
end

function date_time_init_epoch_millis(dt::Base.RefValue{date_time}, ms_since_epoch::UInt64)
    return date_time_init_epoch_millis(Base.unsafe_convert(Ptr{date_time}, dt), ms_since_epoch)
end

function date_time_init_epoch_secs(dt::Ptr{date_time}, sec_ms::Float64)
    precondition(dt != C_NULL)
    frac, integral = modf(sec_ms)
    millis = UInt16(round(frac * TIMESTAMP_MILLIS))
    timestamp = time_t(integral)
    gmt_ref = Ref{tm}()
    local_ref = Ref{tm}()
    gmtime(timestamp, gmt_ref)
    localtime(timestamp, local_ref)
    dt_val = date_time(
        timestamp,
        millis,
        ntuple(_ -> UInt8(0), 6),
        gmt_ref[],
        local_ref[],
        UInt8(0),
    )
    unsafe_store!(dt, dt_val)
    return nothing
end

function date_time_init_epoch_secs(dt::Base.RefValue{date_time}, sec_ms::Float64)
    return date_time_init_epoch_secs(Base.unsafe_convert(Ptr{date_time}, dt), sec_ms)
end

function date_time_init_from_str_cursor(
        dt::Ptr{date_time},
        date_str_cursor::Ptr{ByteCursor},
        fmt::date_format,
    )
    precondition(dt != C_NULL)
    precondition(date_str_cursor != C_NULL)
    if unsafe_load(date_str_cursor).len > DATE_TIME_STR_MAX_LEN
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    zero_struct!(dt)

    parsed_time = Ref{tm}()
    successfully_parsed = false
    seconds_offset = Ref{time_t}(0)
    tz_buf = Memory{UInt8}(undef, 6)
    fill!(tz_buf, 0x00)
    utc_assumed = Ref{Bool}(false)

    if fmt == DateFormat.ISO_8601 || fmt == DateFormat.ISO_8601_BASIC || fmt == DateFormat.AUTO_DETECT
        if _parse_iso_8601(unsafe_load(date_str_cursor), Base.unsafe_convert(Ptr{tm}, parsed_time), seconds_offset)
            utc_assumed[] = true
            successfully_parsed = true
        end
    end

    if fmt == DateFormat.RFC822 || (fmt == DateFormat.AUTO_DETECT && !successfully_parsed)
        if _parse_rfc_822(date_str_cursor, Base.unsafe_convert(Ptr{tm}, parsed_time), tz_buf, utc_assumed)
            successfully_parsed = true
            if utc_assumed[]
                if tz_buf[1] == UInt8('+') || tz_buf[1] == UInt8('-')
                    hour_str = Memory{UInt8}(undef, 3)
                    min_str = Memory{UInt8}(undef, 3)
                    hour_str[1] = tz_buf[2]
                    hour_str[2] = tz_buf[3]
                    hour_str[3] = 0x00
                    min_str[1] = tz_buf[4]
                    min_str[2] = tz_buf[5]
                    min_str[3] = 0x00
                    hour = ccall(:strtol, Clong, (Ptr{UInt8}, Ptr{Ptr{UInt8}}, Cint), pointer(hour_str), C_NULL, 10)
                    min = ccall(:strtol, Clong, (Ptr{UInt8}, Ptr{Ptr{UInt8}}, Cint), pointer(min_str), C_NULL, 10)
                    seconds_offset[] = time_t(hour * 3600 + min * 60)
                    if tz_buf[1] == UInt8('-')
                        seconds_offset[] = -seconds_offset[]
                    end
                end
            end
        end
    end

    if !successfully_parsed
        return raise_error(ERROR_INVALID_DATE_STR)
    end

    timestamp = if utc_assumed[] || seconds_offset[] != 0
        timegm(Base.unsafe_convert(Ptr{tm}, parsed_time))
    else
        ccall(:mktime, time_t, (Ptr{tm},), Base.unsafe_convert(Ptr{tm}, parsed_time))
    end

    timestamp -= seconds_offset[]

    gmt_time = Ref{tm}()
    local_time = Ref{tm}()
    gmtime(timestamp, gmt_time)
    localtime(timestamp, local_time)
    dt_val = date_time(
        timestamp,
        UInt16(0),
        ntuple(i -> tz_buf[i], 6),
        gmt_time[],
        local_time[],
        utc_assumed[] ? UInt8(1) : UInt8(0),
    )
    unsafe_store!(dt, dt_val)
    return OP_SUCCESS
end

function date_time_init_from_str_cursor(
        dt::Base.RefValue{date_time},
        date_str_cursor::Base.RefValue{ByteCursor},
        fmt::date_format,
    )
    return date_time_init_from_str_cursor(
        Base.unsafe_convert(Ptr{date_time}, dt),
        Base.unsafe_convert(Ptr{ByteCursor}, date_str_cursor),
        fmt,
    )
end

function date_time_init_from_str(
        dt::Ptr{date_time},
        date_str::Ptr{ByteBuffer},
        fmt::date_format,
    )
    precondition(dt != C_NULL)
    precondition(date_str != C_NULL)
    if unsafe_load(date_str).len > DATE_TIME_STR_MAX_LEN
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    date_cursor = byte_cursor_from_buf(date_str)
    return date_time_init_from_str_cursor(dt, Ref(date_cursor), fmt)
end

function date_time_init_from_str(
        dt::Base.RefValue{date_time},
        date_str::Base.RefValue{<:ByteBuffer},
        fmt::date_format,
    )
    return date_time_init_from_str(
        Base.unsafe_convert(Ptr{date_time}, dt),
        Base.unsafe_convert(Ptr{ByteBuffer}, date_str),
        fmt,
    )
end

function _date_to_str(tm_val::tm, format_str::AbstractString, output_buf::Ptr{ByteBuffer})
    output_val = unsafe_load(output_buf)
    remaining = output_val.capacity - output_val.len
    fmt_ptr = Base.cconvert(Ptr{UInt8}, format_str)
    bytes_written = Csize_t(0)
    GC.@preserve format_str begin
        bytes_written = ccall(
            :strftime,
            Csize_t,
            (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{tm}),
            pointer(output_val.mem) + output_val.len,
            remaining,
            fmt_ptr,
            Ref(tm_val),
        )
    end
    if bytes_written == 0
        return raise_error(ERROR_SHORT_BUFFER)
    end
    unsafe_store!(output_buf, ByteBuffer(output_val.mem, output_val.len + bytes_written))
    return OP_SUCCESS
end

function date_time_to_local_time_str(
        dt::Ptr{date_time},
        fmt::date_format,
        output_buf::Ptr{ByteBuffer},
    )
    precondition(dt != C_NULL)
    precondition(output_buf != C_NULL)
    debug_assert(fmt != DateFormat.AUTO_DETECT)
    dt_val = unsafe_load(dt)
    if fmt == DateFormat.RFC822
        return _date_to_str(dt_val.local_time, _RFC822_DATE_FORMAT_STR_WITH_Z, output_buf)
    elseif fmt == DateFormat.ISO_8601
        return _date_to_str(dt_val.local_time, _ISO_8601_LONG_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601_BASIC
        return _date_to_str(dt_val.local_time, _ISO_8601_LONG_BASIC_DATE_FORMAT_STR, output_buf)
    end
    return raise_error(ERROR_INVALID_ARGUMENT)
end

function date_time_to_local_time_str(
        dt::Base.RefValue{date_time},
        fmt::date_format,
        output_buf::Base.RefValue{<:ByteBuffer},
    )
    return date_time_to_local_time_str(
        Base.unsafe_convert(Ptr{date_time}, dt),
        fmt,
        Base.unsafe_convert(Ptr{ByteBuffer}, output_buf),
    )
end

function date_time_to_utc_time_str(
        dt::Ptr{date_time},
        fmt::date_format,
        output_buf::Ptr{ByteBuffer},
    )
    precondition(dt != C_NULL)
    precondition(output_buf != C_NULL)
    debug_assert(fmt != DateFormat.AUTO_DETECT)
    dt_val = unsafe_load(dt)
    if fmt == DateFormat.RFC822
        return _date_to_str(dt_val.gmt_time, _RFC822_DATE_FORMAT_STR_MINUS_Z, output_buf)
    elseif fmt == DateFormat.ISO_8601
        return _date_to_str(dt_val.gmt_time, _ISO_8601_LONG_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601_BASIC
        return _date_to_str(dt_val.gmt_time, _ISO_8601_LONG_BASIC_DATE_FORMAT_STR, output_buf)
    end
    return raise_error(ERROR_INVALID_ARGUMENT)
end

function date_time_to_utc_time_str(
        dt::Base.RefValue{date_time},
        fmt::date_format,
        output_buf::Base.RefValue{<:ByteBuffer},
    )
    return date_time_to_utc_time_str(
        Base.unsafe_convert(Ptr{date_time}, dt),
        fmt,
        Base.unsafe_convert(Ptr{ByteBuffer}, output_buf),
    )
end

function date_time_to_local_time_short_str(
        dt::Ptr{date_time},
        fmt::date_format,
        output_buf::Ptr{ByteBuffer},
    )
    precondition(dt != C_NULL)
    precondition(output_buf != C_NULL)
    debug_assert(fmt != DateFormat.AUTO_DETECT)
    dt_val = unsafe_load(dt)
    if fmt == DateFormat.RFC822
        return _date_to_str(dt_val.local_time, _RFC822_SHORT_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601
        return _date_to_str(dt_val.local_time, _ISO_8601_SHORT_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601_BASIC
        return _date_to_str(dt_val.local_time, _ISO_8601_SHORT_BASIC_DATE_FORMAT_STR, output_buf)
    end
    return raise_error(ERROR_INVALID_ARGUMENT)
end

function date_time_to_local_time_short_str(
        dt::Base.RefValue{date_time},
        fmt::date_format,
        output_buf::Base.RefValue{<:ByteBuffer},
    )
    return date_time_to_local_time_short_str(
        Base.unsafe_convert(Ptr{date_time}, dt),
        fmt,
        Base.unsafe_convert(Ptr{ByteBuffer}, output_buf),
    )
end

function date_time_to_utc_time_short_str(
        dt::Ptr{date_time},
        fmt::date_format,
        output_buf::Ptr{ByteBuffer},
    )
    precondition(dt != C_NULL)
    precondition(output_buf != C_NULL)
    debug_assert(fmt != DateFormat.AUTO_DETECT)
    dt_val = unsafe_load(dt)
    if fmt == DateFormat.RFC822
        return _date_to_str(dt_val.gmt_time, _RFC822_SHORT_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601
        return _date_to_str(dt_val.gmt_time, _ISO_8601_SHORT_DATE_FORMAT_STR, output_buf)
    elseif fmt == DateFormat.ISO_8601_BASIC
        return _date_to_str(dt_val.gmt_time, _ISO_8601_SHORT_BASIC_DATE_FORMAT_STR, output_buf)
    end
    return raise_error(ERROR_INVALID_ARGUMENT)
end

function date_time_to_utc_time_short_str(
        dt::Base.RefValue{date_time},
        fmt::date_format,
        output_buf::Base.RefValue{<:ByteBuffer},
    )
    return date_time_to_utc_time_short_str(
        Base.unsafe_convert(Ptr{date_time}, dt),
        fmt,
        Base.unsafe_convert(Ptr{ByteBuffer}, output_buf),
    )
end

function date_time_as_epoch_secs(dt::Ptr{date_time})
    dt_val = unsafe_load(dt)
    return Float64(dt_val.timestamp) + Float64(dt_val.milliseconds) / 1000.0
end

function date_time_as_epoch_secs(dt::Base.RefValue{date_time})
    return date_time_as_epoch_secs(Base.unsafe_convert(Ptr{date_time}, dt))
end

function date_time_as_nanos(dt::Ptr{date_time})
    dt_val = unsafe_load(dt)
    return timestamp_convert(UInt64(dt_val.timestamp), TIMESTAMP_SECS, TIMESTAMP_NANOS, nothing) +
        timestamp_convert(UInt64(dt_val.milliseconds), TIMESTAMP_MILLIS, TIMESTAMP_NANOS, nothing)
end

function date_time_as_nanos(dt::Base.RefValue{date_time})
    return date_time_as_nanos(Base.unsafe_convert(Ptr{date_time}, dt))
end

function date_time_as_millis(dt::Ptr{date_time})
    dt_val = unsafe_load(dt)
    return timestamp_convert(UInt64(dt_val.timestamp), TIMESTAMP_SECS, TIMESTAMP_MILLIS, nothing) +
        UInt64(dt_val.milliseconds)
end

function date_time_as_millis(dt::Base.RefValue{date_time})
    return date_time_as_millis(Base.unsafe_convert(Ptr{date_time}, dt))
end

function date_time_year(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return UInt16(time.tm_year + 1900)
end

function date_time_year(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_year(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_month(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return DateMonth.T(UInt8(time.tm_mon))
end

function date_time_month(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_month(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_month_day(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return UInt8(time.tm_mday)
end

function date_time_month_day(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_month_day(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_day_of_week(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return DayOfWeek.T(UInt8(time.tm_wday))
end

function date_time_day_of_week(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_day_of_week(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_hour(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return UInt8(time.tm_hour)
end

function date_time_hour(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_hour(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_minute(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return UInt8(time.tm_min)
end

function date_time_minute(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_minute(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_second(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return UInt8(time.tm_sec)
end

function date_time_second(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_second(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_dst(dt::Ptr{date_time}, local_time::Bool)
    dt_val = unsafe_load(dt)
    time = local_time ? dt_val.local_time : dt_val.gmt_time
    return time.tm_isdst != 0
end

function date_time_dst(dt::Base.RefValue{date_time}, local_time::Bool)
    return date_time_dst(Base.unsafe_convert(Ptr{date_time}, dt), local_time)
end

function date_time_diff(a::Ptr{date_time}, b::Ptr{date_time})
    return unsafe_load(a).timestamp - unsafe_load(b).timestamp
end

function date_time_diff(a::Base.RefValue{date_time}, b::Base.RefValue{date_time})
    return date_time_diff(Base.unsafe_convert(Ptr{date_time}, a), Base.unsafe_convert(Ptr{date_time}, b))
end
