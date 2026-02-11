# Event loop shared types - included before platform backends

# Event types for IO event subscriptions (bitmask)
@enumx IoEventType::UInt32 begin
    READABLE = 1
    WRITABLE = 2
    REMOTE_HANG_UP = 4
    CLOSED = 8
    ERROR = 16
end
