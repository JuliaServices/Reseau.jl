# AWS IO Library - AWS byte buffer helpers (LibAwsCommon-backed)

@inline function _byte_cursor_from_vec(vec::AbstractVector{UInt8})
    if isempty(vec)
        return LibAwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL))
    end
    return LibAwsCommon.aws_byte_cursor(Csize_t(length(vec)), pointer(vec))
end

@inline function _byte_cursor_from_buf(buf::ByteBuffer)
    if buf.len == 0
        return LibAwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL))
    end
    return LibAwsCommon.aws_byte_cursor(buf.len, pointer(buf.mem))
end

@inline function _byte_buf_from_vec(vec::AbstractVector{UInt8})
    return LibAwsCommon.aws_byte_buf(
        Csize_t(0),
        pointer(vec),
        Csize_t(length(vec)),
        Ptr{LibAwsCommon.aws_allocator}(C_NULL),
    )
end
