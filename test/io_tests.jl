using Test
using AwsIO

@testset "IO library init/cleanup" begin
    AwsIO.io_library_init()
    AwsIO.io_library_init()
    AwsIO.io_fatal_assert_library_initialized()

    @test unsafe_string(AwsIO.error_name(AwsIO.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)) ==
        "ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)) ==
        "Channel cannot accept input"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_PKCS11_CKR_CANCEL)) ==
        "A PKCS#11 (Cryptoki) library function failed with return value CKR_CANCEL"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)) ==
        "Default TLS trust store not found on this system. Trusted CA certificates must be installed, or \"override default trust store\" must be used while creating the TLS context."

    @test AwsIO.log_subject_name(AwsIO.LS_IO_GENERAL) == "aws-c-io"
    @test AwsIO.log_subject_description(AwsIO.LS_IO_GENERAL) ==
        "Subject for IO logging that doesn't belong to any particular category"
    @test AwsIO.log_subject_name(AwsIO.LS_IO_TLS) == "tls-handler"

    @test AwsIO.io_error_code_is_retryable(AwsIO.ERROR_IO_SOCKET_TIMEOUT)
    @test !AwsIO.io_error_code_is_retryable(AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST)

    AwsIO.io_library_clean_up()
    AwsIO.io_library_clean_up()
    @test_throws ErrorException AwsIO.io_fatal_assert_library_initialized()
end

@testset "IO error parity" begin
    root = dirname(@__DIR__)
    header_path = joinpath(root, "aws-c-io", "include", "aws", "io", "io.h")

    if !isfile(header_path)
        @test true
    else
        function parse_aws_io_errors(path::AbstractString)
            names = String[]
            inside_enum = false
            for line in eachline(path)
                if occursin("enum aws_io_errors", line)
                    inside_enum = true
                    continue
                end
                if !inside_enum
                    continue
                end
                if occursin("};", line)
                    break
                end
                line = split(line, "//"; limit = 2)[1]
                line = split(line, "/*"; limit = 2)[1]
                line = strip(line)
                isempty(line) && continue
                line = replace(line, "," => "")
                name = strip(first(split(line, "="; limit = 2)))
                if startswith(name, "AWS_") || startswith(name, "DEPRECATED_")
                    push!(names, name)
                end
            end
            return names
        end

        function map_aws_error_name(name::AbstractString)
            if name == "AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT"
                return "ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT"
            elseif name == "DEPRECATED_AWS_IO_INVALID_FILE_HANDLE"
                return "ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED"
            elseif name == "AWS_IO_ERROR_END_RANGE"
                return "ERROR_IO_END_RANGE"
            elseif startswith(name, "AWS_ERROR_IO_")
                return "ERROR_" * name[11:end]
            elseif startswith(name, "AWS_IO_")
                return "ERROR_" * name[5:end]
            elseif startswith(name, "AWS_ERROR_")
                return "ERROR_IO_" * name[11:end]
            else
                return "ERROR_" * String(name)
            end
        end

        missing = String[]
        for name in parse_aws_io_errors(header_path)
            mapped = Symbol(map_aws_error_name(name))
            if !isdefined(AwsIO, mapped)
                push!(missing, String(mapped))
            end
        end

        @test isempty(missing)
    end
end

@testset "Socket errno mapping parity" begin
    if Sys.iswindows()
        @test true
    else
        @test AwsIO.determine_socket_error(AwsIO.ECONNREFUSED) ==
            AwsIO.ERROR_IO_SOCKET_CONNECTION_REFUSED
        @test AwsIO.determine_socket_error(AwsIO.ECONNRESET) ==
            AwsIO.ERROR_IO_SOCKET_CLOSED
        @test AwsIO.determine_socket_error(AwsIO.ETIMEDOUT) ==
            AwsIO.ERROR_IO_SOCKET_TIMEOUT
        @test AwsIO.determine_socket_error(AwsIO.EHOSTUNREACH) ==
            AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test AwsIO.determine_socket_error(AwsIO.ENETUNREACH) ==
            AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test AwsIO.determine_socket_error(AwsIO.EADDRNOTAVAIL) ==
            AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
        @test AwsIO.determine_socket_error(AwsIO.ENETDOWN) ==
            AwsIO.ERROR_IO_SOCKET_NETWORK_DOWN
        @test AwsIO.determine_socket_error(AwsIO.ECONNABORTED) ==
            AwsIO.ERROR_IO_SOCKET_CONNECT_ABORTED
        @test AwsIO.determine_socket_error(AwsIO.EADDRINUSE) ==
            AwsIO.ERROR_IO_SOCKET_ADDRESS_IN_USE
        @test AwsIO.determine_socket_error(AwsIO.ENOBUFS) ==
            AwsIO.ERROR_OOM
        @test AwsIO.determine_socket_error(AwsIO.ENOMEM) ==
            AwsIO.ERROR_OOM
        @test AwsIO.determine_socket_error(AwsIO.EAGAIN) ==
            AwsIO.ERROR_IO_READ_WOULD_BLOCK
        @test AwsIO.determine_socket_error(AwsIO.EWOULDBLOCK) ==
            AwsIO.ERROR_IO_READ_WOULD_BLOCK
        @test AwsIO.determine_socket_error(AwsIO.EMFILE) ==
            AwsIO.ERROR_MAX_FDS_EXCEEDED
        @test AwsIO.determine_socket_error(AwsIO.ENFILE) ==
            AwsIO.ERROR_MAX_FDS_EXCEEDED
        @test AwsIO.determine_socket_error(AwsIO.ENOENT) ==
            AwsIO.ERROR_FILE_INVALID_PATH
        @test AwsIO.determine_socket_error(AwsIO.EINVAL) ==
            AwsIO.ERROR_FILE_INVALID_PATH
        @test AwsIO.determine_socket_error(AwsIO.EAFNOSUPPORT) ==
            AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
        @test AwsIO.determine_socket_error(AwsIO.EACCES) ==
            AwsIO.ERROR_NO_PERMISSION
        @test AwsIO.determine_socket_error(9999) ==
            AwsIO.ERROR_IO_SOCKET_NOT_CONNECTED
    end
end
