const StatisticsCategory = UInt32

const STATISTICS_CATEGORY_STRIDE_BITS = 8
const STATISTICS_CATEGORY_STRIDE = UInt32(1) << STATISTICS_CATEGORY_STRIDE_BITS

STATISTICS_CATEGORY_BEGIN_RANGE(x) = StatisticsCategory(x) * STATISTICS_CATEGORY_STRIDE
STATISTICS_CATEGORY_END_RANGE(x) = (StatisticsCategory(x) + 1) * STATISTICS_CATEGORY_STRIDE - 1

const STAT_CAT_INVALID = STATISTICS_CATEGORY_BEGIN_RANGE(COMMON_PACKAGE_ID)

struct StatisticsBase
    category::StatisticsCategory
end

struct StatisticsSampleInterval
    begin_time_ms::UInt64
    end_time_ms::UInt64
end

abstract type StatisticsHandler end

process_statistics(::StatisticsHandler, ::StatisticsSampleInterval, ::ArrayList) = nothing
report_interval_ms(::StatisticsHandler) = UInt64(0)
close!(::StatisticsHandler) = nothing
