# AWS IO Library - Statistics
# Port of aws-c-io/include/aws/io/statistics.h and source/statistics.c

@enumx TlsNegotiationStatus::UInt8 begin
    NONE = 0
    ONGOING = 1
    SUCCESS = 2
    FAILURE = 3
end

const STAT_CAT_SOCKET = STATISTICS_CATEGORY_BEGIN_RANGE(IO_PACKAGE_ID)
const STAT_CAT_TLS = STAT_CAT_SOCKET + 1

mutable struct SocketHandlerStatistics
    category::StatisticsCategory
    bytes_read::UInt64
    bytes_written::UInt64
end

SocketHandlerStatistics() = SocketHandlerStatistics(STAT_CAT_SOCKET, UInt64(0), UInt64(0))

function crt_statistics_socket_init!(stats::SocketHandlerStatistics)::Nothing
    stats.category = STAT_CAT_SOCKET
    stats.bytes_read = 0
    stats.bytes_written = 0
    return nothing
end

function crt_statistics_socket_cleanup!(stats::SocketHandlerStatistics)::Nothing
    _ = stats
    return nothing
end

function crt_statistics_socket_reset!(stats::SocketHandlerStatistics)::Nothing
    stats.bytes_read = 0
    stats.bytes_written = 0
    return nothing
end

mutable struct TlsHandlerStatistics
    category::StatisticsCategory
    handshake_start_ns::UInt64
    handshake_end_ns::UInt64
    handshake_status::TlsNegotiationStatus.T
end

TlsHandlerStatistics() = TlsHandlerStatistics(STAT_CAT_TLS, UInt64(0), UInt64(0), TlsNegotiationStatus.NONE)

function crt_statistics_tls_init!(stats::TlsHandlerStatistics)::Nothing
    stats.category = STAT_CAT_TLS
    stats.handshake_start_ns = 0
    stats.handshake_end_ns = 0
    stats.handshake_status = TlsNegotiationStatus.NONE
    return nothing
end

function crt_statistics_tls_cleanup!(stats::TlsHandlerStatistics)::Nothing
    _ = stats
    return nothing
end

function crt_statistics_tls_reset!(stats::TlsHandlerStatistics)::Nothing
    _ = stats
    return nothing
end
