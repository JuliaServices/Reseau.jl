# Internal Clang Blocks ABI helpers (macOS).
#
# These let us call Apple Network.framework / Security.framework APIs that take
# blocks, without needing a separate C shim library.
module BlocksABI

const _LIBSYSTEM = "libSystem"

# Blocks flags (from libBlocksRuntime / Clang blocks ABI).
const BLOCK_NEEDS_FREE = UInt32(1) << 24
const BLOCK_HAS_COPY_DISPOSE = UInt32(1) << 25
const BLOCK_IS_GLOBAL = UInt32(1) << 28
const BLOCK_HAS_SIGNATURE = UInt32(1) << 30

struct BlockDescriptor1
    reserved::UInt64
    size::UInt64
end

struct BlockLiteralHeader
    isa::Ptr{Cvoid}
    flags::UInt32
    reserved::UInt32
    invoke::Ptr{Cvoid}
    descriptor::Ptr{Cvoid}
end

struct BlockLiteralCtx
    isa::Ptr{Cvoid}
    flags::UInt32
    reserved::UInt32
    invoke::Ptr{Cvoid}
    descriptor::Ptr{Cvoid}
    ctx::Ptr{Cvoid}
end

# Copied blocks keep a pointer to the descriptor, so it must outlive all blocks.
const _DESC_CTX = Ref{Ptr{Cvoid}}(C_NULL)

function _descriptor_ctx_ptr()::Ptr{Cvoid}
    p = _DESC_CTX[]
    if p != C_NULL
        return p
    end

    dp = Base.Libc.malloc(sizeof(BlockDescriptor1))
    dp == C_NULL && error("malloc failed for BlockDescriptor1")
    unsafe_store!(Ptr{BlockDescriptor1}(dp), BlockDescriptor1(0, sizeof(BlockLiteralCtx)))
    _DESC_CTX[] = Ptr{Cvoid}(dp)
    return _DESC_CTX[]
end

@inline function _nsconcrete_stack_block()::Ptr{Cvoid}
    # `_NSConcreteStackBlock` is declared as `void * _NSConcreteStackBlock[32]`.
    # For blocks, `isa` points at this global (i.e. its address).
    return Ptr{Cvoid}(cglobal((:_NSConcreteStackBlock, _LIBSYSTEM), Ptr{Cvoid}))
end

@inline function block_copy(block::Ptr{Cvoid})::Ptr{Cvoid}
    return ccall((:_Block_copy, _LIBSYSTEM), Ptr{Cvoid}, (Ptr{Cvoid},), block)
end

@inline function block_release(block::Ptr{Cvoid})::Cvoid
    ccall((:_Block_release, _LIBSYSTEM), Cvoid, (Ptr{Cvoid},), block)
    return
end

@inline function block_invoke_ptr(block::Ptr{Cvoid})::Ptr{Cvoid}
    hdr = unsafe_load(Ptr{BlockLiteralHeader}(block))
    return hdr.invoke
end

@inline function call_block_void_bool(block::Ptr{Cvoid}, result::Bool)::Cvoid
    # For blocks of signature: `void (^)(bool)`, e.g. `sec_protocol_verify_complete_t`.
    invoke = block_invoke_ptr(block)
    ccall(invoke, Cvoid, (Ptr{Cvoid}, UInt8), block, result ? UInt8(1) : UInt8(0))
    return
end

@inline function captured_ctx(block::Ptr{Cvoid})::Ptr{Cvoid}
    lit = unsafe_load(Ptr{BlockLiteralCtx}(block))
    return lit.ctx
end

mutable struct StackBlock
    ptr::Ptr{Cvoid}
end

"""
    make_stack_block_ctx(invoke_ptr, ctx_ptr; flags=0)

Create a stack-style block (isa = `_NSConcreteStackBlock`) whose captured data
is a single `void* ctx`.

Memory is allocated via `malloc` and must be freed via `free!(::StackBlock)`.
The descriptor is a singleton allocated once and intentionally never freed,
since copied blocks keep a pointer to it (matching compiler-emitted blocks).

Note: this is a "stack" block in ABI terms, even though storage is heap-allocated
here. That makes it safe if a consumer fails to copy the block (it still points
to valid memory we own), and also safe if a consumer *does* copy it (uses
descriptor->size).
"""
function make_stack_block_ctx(invoke::Ptr{Cvoid}, ctx::Ptr{Cvoid}; flags::UInt32 = UInt32(0))::StackBlock
    desc_ptr = _descriptor_ctx_ptr()
    blk = BlockLiteralCtx(_nsconcrete_stack_block(), flags, 0, invoke, desc_ptr, ctx)
    blk_ptr = Base.Libc.malloc(sizeof(BlockLiteralCtx))
    blk_ptr == C_NULL && error("malloc failed for BlockLiteralCtx")
    unsafe_store!(Ptr{BlockLiteralCtx}(blk_ptr), blk)
    return StackBlock(Ptr{Cvoid}(blk_ptr))
end

function free!(blk::StackBlock)
    blk.ptr != C_NULL && Base.Libc.free(blk.ptr)
    blk.ptr = C_NULL
    return nothing
end

end # module BlocksABI
