# AWS IO Library - Winsock init helpers
# Port of aws-c-io/source/windows/winsock_init.c

@static if Sys.iswindows()
    const _WS2_32 = "Ws2_32"
    const _KERNEL32 = "Kernel32"

    const _winsock_init_lock = ReentrantLock()
    const _winsock_initialized = Ref{Bool}(false)
    const _connectex_fn = Ref{Ptr{Cvoid}}(C_NULL)
    const _acceptex_fn = Ref{Ptr{Cvoid}}(C_NULL)

    const AF_INET = Cint(2)
    const SOCK_STREAM = Cint(1)

    const INVALID_SOCKET = UInt(typemax(UInt))

    const SIO_GET_EXTENSION_FUNCTION_POINTER = UInt32(0xC8000006)

    struct GUID
        Data1::UInt32
        Data2::UInt16
        Data3::UInt16
        Data4::NTuple{8, UInt8}
    end

    # Values from mswsock.h
    const WSAID_CONNECTEX = GUID(
        0x25a207b9,
        0xddf3,
        0x4660,
        (0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e),
    )
    const WSAID_ACCEPTEX = GUID(
        0xb5367df1,
        0xcbac,
        0x11cf,
        (0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92),
    )

    struct WSADATA
        wVersion::UInt16
        wHighVersion::UInt16
        szDescription::NTuple{257, UInt8}
        szSystemStatus::NTuple{129, UInt8}
        iMaxSockets::UInt16
        iMaxUdpDg::UInt16
        lpVendorInfo::Ptr{UInt8}
    end

    @inline function _wsa_get_last_error()::Cint
        return ccall((:WSAGetLastError, _WS2_32), Cint, ())
    end

    function winsock_check_and_init!()::Union{Nothing, ErrorResult}
        if _winsock_initialized[]
            return nothing
        end

        lock(_winsock_init_lock)
        try
            if _winsock_initialized[]
                return nothing
            end

            logf(LogLevel.INFO, LS_IO_SOCKET, "static: initializing WinSock")

            requested_version = UInt16(0x0202) # MAKEWORD(2, 2)
            wsa_data = Ref(WSADATA(0x0, 0x0, ntuple(_ -> UInt8(0), 257), ntuple(_ -> UInt8(0), 129), 0x0, 0x0, C_NULL))
            rc = ccall((:WSAStartup, _WS2_32), Cint, (UInt16, Ptr{WSADATA}), requested_version, wsa_data)
            if rc != 0
                logf(LogLevel.ERROR, LS_IO_SOCKET, "static: WinSock initialization failed with error %d", rc)
                raise_error(ERROR_SYS_CALL_FAILURE)
                return ErrorResult(ERROR_SYS_CALL_FAILURE)
            end

            dummy = ccall((:socket, _WS2_32), UInt, (Cint, Cint, Cint), AF_INET, SOCK_STREAM, Cint(0))
            if dummy == INVALID_SOCKET
                err = _wsa_get_last_error()
                logf(LogLevel.ERROR, LS_IO_SOCKET, "static: dummy socket() failed with WSAError %d", err)
                raise_error(ERROR_SYS_CALL_FAILURE)
                return ErrorResult(ERROR_SYS_CALL_FAILURE)
            end

            try
                logf(LogLevel.INFO, LS_IO_SOCKET, "static: loading WSAID_CONNECTEX function")
                bytes_written = Ref{UInt32}(0)
                connectex_ref = Ref{Ptr{Cvoid}}(C_NULL)
                guid = Ref(WSAID_CONNECTEX)
                rc = ccall(
                    (:WSAIoctl, _WS2_32),
                    Cint,
                    (UInt, UInt32, Ptr{GUID}, UInt32, Ptr{Ptr{Cvoid}}, UInt32, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}),
                    dummy,
                    SIO_GET_EXTENSION_FUNCTION_POINTER,
                    guid,
                    UInt32(sizeof(GUID)),
                    connectex_ref,
                    UInt32(sizeof(Ptr{Cvoid})),
                    bytes_written,
                    C_NULL,
                    C_NULL,
                )
                if rc != 0 || connectex_ref[] == C_NULL
                    err = _wsa_get_last_error()
                    logf(LogLevel.ERROR, LS_IO_SOCKET, "static: failed to load WSAID_CONNECTEX with WSAError %d", err)
                    raise_error(ERROR_SYS_CALL_FAILURE)
                    return ErrorResult(ERROR_SYS_CALL_FAILURE)
                end
                _connectex_fn[] = connectex_ref[]

                logf(LogLevel.INFO, LS_IO_SOCKET, "static: loading WSAID_ACCEPTEX function")
                bytes_written[] = 0
                acceptex_ref = Ref{Ptr{Cvoid}}(C_NULL)
                guid2 = Ref(WSAID_ACCEPTEX)
                rc = ccall(
                    (:WSAIoctl, _WS2_32),
                    Cint,
                    (UInt, UInt32, Ptr{GUID}, UInt32, Ptr{Ptr{Cvoid}}, UInt32, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}),
                    dummy,
                    SIO_GET_EXTENSION_FUNCTION_POINTER,
                    guid2,
                    UInt32(sizeof(GUID)),
                    acceptex_ref,
                    UInt32(sizeof(Ptr{Cvoid})),
                    bytes_written,
                    C_NULL,
                    C_NULL,
                )
                if rc != 0 || acceptex_ref[] == C_NULL
                    err = _wsa_get_last_error()
                    logf(LogLevel.ERROR, LS_IO_SOCKET, "static: failed to load WSAID_ACCEPTEX with WSAError %d", err)
                    raise_error(ERROR_SYS_CALL_FAILURE)
                    return ErrorResult(ERROR_SYS_CALL_FAILURE)
                end
                _acceptex_fn[] = acceptex_ref[]
            finally
                _ = ccall((:closesocket, _WS2_32), Cint, (UInt,), dummy)
            end

            _winsock_initialized[] = true
            return nothing
        finally
            unlock(_winsock_init_lock)
        end
    end

    function winsock_get_connectex_fn()::Union{Ptr{Cvoid}, ErrorResult}
        res = winsock_check_and_init!()
        res isa ErrorResult && return res
        if _connectex_fn[] == C_NULL
            raise_error(ERROR_SYS_CALL_FAILURE)
            return ErrorResult(ERROR_SYS_CALL_FAILURE)
        end
        return _connectex_fn[]
    end

    function winsock_get_acceptex_fn()::Union{Ptr{Cvoid}, ErrorResult}
        res = winsock_check_and_init!()
        res isa ErrorResult && return res
        if _acceptex_fn[] == C_NULL
            raise_error(ERROR_SYS_CALL_FAILURE)
            return ErrorResult(ERROR_SYS_CALL_FAILURE)
        end
        return _acceptex_fn[]
    end
else
    function winsock_check_and_init!()::Union{Nothing, ErrorResult}
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    function winsock_get_connectex_fn()::Union{Ptr{Cvoid}, ErrorResult}
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    function winsock_get_acceptex_fn()::Union{Ptr{Cvoid}, ErrorResult}
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end
