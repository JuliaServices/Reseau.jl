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
