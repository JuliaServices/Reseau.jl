# Compat helpers for byte buffers on Julia versions before `Memory` exists.

if VERSION < v"1.11"
    const ByteMemory = Vector{UInt8}
    bytememory(n::Integer)::ByteMemory = Vector{UInt8}(undef, Int(n))
else
    const ByteMemory = Memory{UInt8}
    bytememory(n::Integer)::ByteMemory = Memory{UInt8}(undef, Int(n))
end
