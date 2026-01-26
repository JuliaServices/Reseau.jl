@enumx CpuFeature::UInt8 begin
    CLMUL = 0
    SSE_4_1 = 1
    SSE_4_2 = 2
    AVX2 = 3
    AVX512 = 4
    ARM_CRC = 5
    BMI2 = 6
    VPCLMULQDQ = 7
    ARM_PMULL = 8
    ARM_CRYPTO = 9
end

const cpu_feature = CpuFeature.T
const CPU_FEATURE_COUNT = Int(CpuFeature.ARM_CRYPTO) + 1

const _cpu_features = fill(false, CPU_FEATURE_COUNT)

@inline _feature_index(feature::cpu_feature) = Int(feature) + 1
const _cpu_features_cached = Ref{Bool}(false)

@static if Sys.ARCH == :x86_64 || Sys.ARCH == :i686
    @generated function _run_cpuid(eax::UInt32, ecx::UInt32)
        quote
            Base.llvmcall(
                """
                %res = call { i32, i32, i32, i32 } @llvm.x86.cpuid(i32 %0, i32 %1)
                ret { i32, i32, i32, i32 } %res
                """,
                NTuple{4, UInt32},
                Tuple{UInt32, UInt32},
                eax,
                ecx,
            )
        end
    end

    @generated function _run_xgetbv(xcr::UInt32)
        quote
            Base.llvmcall(
                """
                %res = call i64 @llvm.x86.xgetbv(i32 %0)
                ret i64 %res
                """,
                UInt64,
                Tuple{UInt32},
                xcr,
            )
        end
    end
end

function _cache_cpu_features_x86()
    abcd = _run_cpuid(0x0, 0x0)
    max_cpuid = abcd[1]
    if max_cpuid < 0x1
        return nothing
    end
    abcd = _run_cpuid(0x1, 0x0)
    ecx = abcd[3]
    _cpu_features[_feature_index(CpuFeature.CLMUL)] = (ecx & (1 << 1)) != 0
    _cpu_features[_feature_index(CpuFeature.SSE_4_1)] = (ecx & (1 << 19)) != 0
    _cpu_features[_feature_index(CpuFeature.SSE_4_2)] = (ecx & (1 << 20)) != 0

    avx_usable = false
    avx512_usable = false
    if (ecx & (1 << 27)) != 0
        xcr0 = _run_xgetbv(0)
        avx_mask = (UInt64(1) << 1) | (UInt64(1) << 2)
        avx_usable = (xcr0 & avx_mask) == avx_mask
        avx512_mask = avx_mask | (UInt64(1) << 5) | (UInt64(1) << 6) | (UInt64(1) << 7)
        avx512_usable = (xcr0 & avx512_mask) == avx512_mask
    end

    feature_avx = false
    if avx_usable
        feature_avx = (ecx & (1 << 28)) != 0
    end

    if max_cpuid < 0x7
        return nothing
    end
    abcd = _run_cpuid(0x7, 0x0)
    ebx = abcd[2]
    ecx_ext = abcd[3]
    _cpu_features[_feature_index(CpuFeature.BMI2)] = (ebx & (1 << 8)) != 0
    if feature_avx
        if avx_usable
            _cpu_features[_feature_index(CpuFeature.AVX2)] = (ebx & (1 << 5)) != 0
            _cpu_features[_feature_index(CpuFeature.VPCLMULQDQ)] = (ecx_ext & (1 << 10)) != 0
        end
        if avx512_usable
            _cpu_features[_feature_index(CpuFeature.AVX512)] = (ebx & (1 << 16)) != 0
        end
    end
    return nothing
end

@static if Sys.ARCH == :aarch64 || Sys.ARCH == :armv7l || Sys.ARCH == :armv6l
    const _AT_HWCAP = 16
    const _AT_HWCAP2 = 26
    const _hwcap_cached = Ref{Bool}(false)
    const _hwcap = Ref{UInt}(0)
    const _hwcap2 = Ref{UInt}(0)

    function _cache_hwcap()
        _hwcap[] = UInt(ccall(:getauxval, Culong, (Culong,), _AT_HWCAP))
        _hwcap2[] = UInt(ccall(:getauxval, Culong, (Culong,), _AT_HWCAP2))
        _hwcap_cached[] = true
        return nothing
    end
end

@static if _PLATFORM_APPLE && (Sys.ARCH == :aarch64)
    function _sysctl_feature(name::AbstractString)
        value = Ref{Int64}(0)
        size = Ref{Csize_t}(sizeof(value[]))
        name_ptr = Base.cconvert(Ptr{UInt8}, name)
        GC.@preserve name begin
            if ccall(
                :sysctlbyname,
                Cint,
                (Ptr{UInt8}, Ptr{Cvoid}, Ptr{Csize_t}, Ptr{Cvoid}, Csize_t),
                name_ptr,
                value,
                size,
                C_NULL,
                0,
            ) != 0
                return nothing
            end
        end
        return value[] == 1
    end
end

function _cache_cpu_features_arm()
    @static if _PLATFORM_LINUX
        if !_hwcap_cached[]
            _cache_hwcap()
        end
        if Sys.ARCH == :aarch64
            _cpu_features[_feature_index(CpuFeature.ARM_CRC)] = (_hwcap[] & (UInt(1) << 7)) != 0
            _cpu_features[_feature_index(CpuFeature.ARM_PMULL)] = (_hwcap[] & (UInt(1) << 4)) != 0
            _cpu_features[_feature_index(CpuFeature.ARM_CRYPTO)] = (_hwcap[] & (UInt(1) << 3)) != 0
        else
            _cpu_features[_feature_index(CpuFeature.ARM_CRC)] = (_hwcap2[] & (UInt(1) << 4)) != 0
        end
    elseif _PLATFORM_APPLE
        pmull = _sysctl_feature("hw.optional.arm.FEAT_PMULL")
        if pmull !== nothing
            _cpu_features[_feature_index(CpuFeature.ARM_PMULL)] = pmull
        end
        crc = _sysctl_feature("hw.optional.armv8_crc32")
        if crc !== nothing
            _cpu_features[_feature_index(CpuFeature.ARM_CRC)] = crc
        end
        aes = _sysctl_feature("hw.optional.arm.FEAT_AES")
        if aes !== nothing
            _cpu_features[_feature_index(CpuFeature.ARM_CRYPTO)] = aes
        end
    elseif _PLATFORM_WINDOWS
        const _PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE = 31
        const _PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE = 30
        _cpu_features[_feature_index(CpuFeature.ARM_CRC)] = ccall(
            (:IsProcessorFeaturePresent, "kernel32"),
            UInt8,
            (UInt32,),
            UInt32(_PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE),
        ) != 0
        crypto = ccall(
            (:IsProcessorFeaturePresent, "kernel32"),
            UInt8,
            (UInt32,),
            UInt32(_PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE),
        ) != 0
        _cpu_features[_feature_index(CpuFeature.ARM_PMULL)] = crypto
        _cpu_features[_feature_index(CpuFeature.ARM_CRYPTO)] = crypto
    end
    return nothing
end

function _cache_cpu_features()
    @static if Sys.ARCH == :x86_64 || Sys.ARCH == :i686
        _cache_cpu_features_x86()
    elseif Sys.ARCH == :aarch64 || Sys.ARCH == :armv7l || Sys.ARCH == :armv6l
        _cache_cpu_features_arm()
    end
    _cpu_features_cached[] = true
    return nothing
end

function cpu_has_feature(feature::cpu_feature)
    if !_cpu_features_cached[]
        _cache_cpu_features()
    end
    idx = _feature_index(feature)
    debug_assert(1 <= idx && idx <= CPU_FEATURE_COUNT)
    return _cpu_features[idx]
end

const _cpuid_state = Ref{Int}(2)

function common_private_has_avx2()
    @static if !(Sys.ARCH == :x86_64 || Sys.ARCH == :i686)
        return false
    end
    if _cpuid_state[] == 0
        return true
    elseif _cpuid_state[] == 1
        return false
    end
    env_name_ptr = Base.cconvert(Ptr{UInt8}, "AWS_COMMON_AVX2")
    env_val = Ptr{UInt8}(C_NULL)
    GC.@preserve env_name_ptr begin
        env_val = ccall(:getenv, Ptr{UInt8}, (Ptr{UInt8},), env_name_ptr)
    end
    if env_val != C_NULL
        enabled = ccall(:atoi, Cint, (Ptr{UInt8},), env_val) != 0
        _cpuid_state[] = enabled ? 0 : 1
        return enabled
    end
    available = cpu_has_feature(CpuFeature.AVX2)
    _cpuid_state[] = available ? 0 : 1
    return available
end
