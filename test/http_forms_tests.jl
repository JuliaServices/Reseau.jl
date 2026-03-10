using Test
using Reseau

const HT = Reseau.HTTP

function _read_all_form_body(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 16)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

function _multipart_fixture_body()::Vector{UInt8}
    return Vector{UInt8}(join([
        "----------------------------918073721150061572809433",
        "Content-Disposition: form-data; name=\"namevalue\"; filename=\"multipart.txt\"",
        "Content-Type: text/plain",
        "",
        "not much to say",
        "----------------------------918073721150061572809433",
        "Content-Disposition: form-data; name=\"key1\"",
        "",
        "1",
        "----------------------------918073721150061572809433--",
        "",
    ], "\r\n"))
end

@testset "HTTP forms and sniff helpers" begin
    form = HT.Form(Dict("text" => "hello"))
    @test startswith(HT.content_type(form), "multipart/form-data; boundary=")
    mark(form)
    payload = read(form)
    payload_text = String(copy(payload))
    reset(form)
    @test occursin("Content-Disposition: form-data; name=\"text\"", payload_text)
    @test occursin("hello", payload_text)
    @test read(form) == payload

    multipart = HT.Multipart(nothing, IOBuffer("some data"), "text/plain", "", "testname")
    shown = sprint(show, multipart)
    @test occursin("contenttype=\"text/plain\"", shown)
    @test HT.Multipart(nothing, IOBuffer("bytes")) isa HT.Multipart
    @test_throws MethodError HT.Multipart(nothing, "bytes", "text/plain", "", "testname")

    @test HT.Form(Dict(); boundary = "a") isa HT.Form
    @test HT.Form(Dict(); boundary = " Aa1'()+,-.:=?") isa HT.Form
    @test HT.Form(Dict(); boundary = 'a'^70) isa HT.Form
    @test_throws AssertionError HT.Form(Dict(); boundary = "")
    @test_throws AssertionError HT.Form(Dict(); boundary = 'a'^71)
    @test_throws AssertionError HT.Form(Dict(); boundary = "a ")

    body = _multipart_fixture_body()
    parsed = HT.parse_multipart_form(
        "multipart/form-data; boundary=--------------------------918073721150061572809433",
        body,
    )
    @test parsed !== nothing
    @test length(parsed::Vector) == 2
    @test parsed[1].name == "namevalue"
    @test parsed[1].filename == "multipart.txt"
    @test String(read(parsed[1])) == "not much to say"
    @test parsed[2].name == "key1"
    @test String(read(parsed[2])) == "1"

    @test HT.sniff(IOBuffer("Hello world")) == "text/plain; charset=utf-8"
    @test HT.sniff(IOBuffer("{\"a\":1}")) == "application/json; charset=utf-8"
end

@testset "HTTP request body helpers" begin
    string_bytes, string_content_type = HT._materialize_request_body_bytes("hello")
    @test string_bytes isa Base.CodeUnits{UInt8, String}
    @test String(string_bytes) == "hello"
    @test string_content_type === nothing

    raw = UInt8[0x61, 0x62, 0x63]
    raw_view = @view(raw[2:3])
    view_bytes, view_content_type = HT._materialize_request_body_bytes(raw_view)
    @test view_bytes === raw_view
    @test view_content_type === nothing

    bytes, content_type = HT._materialize_request_body_bytes(Dict("name" => "value with spaces"))
    @test String(bytes) == "name=value%20with%20spaces"
    @test content_type == "application/x-www-form-urlencoded"

    bytes_named, content_type_named = HT._materialize_request_body_bytes((name = "value",))
    @test String(bytes_named) == "name=value"
    @test content_type_named == "application/x-www-form-urlencoded"

    form = HT.Form(Dict("field" => "value"))
    bytes_form, content_type_form = HT._materialize_request_body_bytes(form)
    @test startswith(content_type_form::String, "multipart/form-data; boundary=")
    @test occursin("field", String(bytes_form))

    iterable_body = HT._iterable_body(["hey", " there ", "sailor"])
    @test String(_read_all_form_body(iterable_body)) == "hey there sailor"

    io_body = HT._streaming_io_body(IOBuffer("stream body"))
    @test String(_read_all_form_body(io_body)) == "stream body"

    normalized_view = HT._normalize_body_input(raw_view)
    @test normalized_view.body isa HT.BytesBody
    @test normalized_view.body.data === raw_view
    @test normalized_view.content_length == 2
    @test normalized_view.replayable

    normalized = HT._normalized_request_body(HT.BytesBody(UInt8[0x61]), 1; default_content_type = "text/plain", replayable = true)
    @test normalized.body isa HT.BytesBody
    @test normalized.content_length == 1
    @test normalized.default_content_type == "text/plain"
    @test normalized.replayable
end
