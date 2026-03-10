using Test
using Reseau

const HT = Reseau.HTTP

function _set_cookie_headers(values::AbstractString...)::HT.Headers
    headers = HT.Headers()
    for value in values
        HT.add_header!(headers, "Set-Cookie", value)
    end
    return headers
end

@testset "HTTP cookie parsing and stringifying" begin
    headers = _set_cookie_headers("sid=abc; Path=/; Domain=.example.com; Max-Age=60; HttpOnly; Secure; SameSite=Lax")
    response = HT.Response(200; headers = headers)
    parsed = HT.cookies(response)
    @test length(parsed) == 1
    cookie = parsed[1]
    @test cookie.name == "sid"
    @test cookie.value == "abc"
    @test cookie.path == "/"
    @test cookie.domain == ".example.com"
    @test cookie.maxage == 60
    @test cookie.httponly
    @test cookie.secure
    @test cookie.samesite == HT.Cookies.SameSiteLaxMode
    rendered = HT.stringify(cookie, false)
    @test occursin("sid=abc", rendered)
    @test occursin("; Path=/", rendered)
    @test occursin("; Domain=example.com", rendered)
    @test occursin("; Max-Age=60", rendered)
    @test occursin("; HttpOnly", rendered)
    @test occursin("; Secure", rendered)
    @test occursin("; SameSite=Lax", rendered)

    req_headers = HT.Headers()
    HT.add_header!(req_headers, "Cookie", "a=1; b=two")
    request = HT.Request("GET", "/"; headers = req_headers)
    req_cookies = HT.cookies(request)
    @test [(c.name, c.value) for c in req_cookies] == [("a", "1"), ("b", "two")]
end

@testset "HTTP addcookie! appends request and response headers" begin
    request = HT.Request("GET", "/")
    HT.addcookie!(request, HT.Cookie("session", "abc"))
    @test HT.get_headers(request.headers, "Cookie") == ["session=abc"]

    response = HT.Response(200)
    HT.addcookie!(response, HT.Cookie("session", "abc"; path = "/", secure = true))
    values = HT.get_headers(response.headers, "Set-Cookie")
    @test length(values) == 1
    @test occursin("session=abc", values[1])
    @test occursin("; Path=/", values[1])
    @test occursin("; Secure", values[1])
end

@testset "HTTP CookieJar matches host, path, secure, and delete semantics" begin
    jar = HT.CookieJar()
    headers = _set_cookie_headers(
        "root=1; Path=/",
        "docs=2; Path=/docs",
        "domainwide=3; Domain=.example.com; Path=/",
        "secureonly=4; Path=/; Secure",
        "auto=5",
    )
    HT.setcookies!(jar, "https", "example.com", "/docs/index", headers)

    cookies_https = HT.getcookies!(jar, "https", "example.com", "/docs/page")
    names_https = [c.name for c in cookies_https]
    @test "docs" in names_https
    @test "root" in names_https
    @test "domainwide" in names_https
    @test "secureonly" in names_https
    @test "auto" in names_https
    @test Set(names_https[1:2]) == Set(["auto", "docs"])

    cookies_http = HT.getcookies!(jar, "http", "example.com", "/docs/page")
    @test !("secureonly" in [c.name for c in cookies_http])

    cookies_subdomain = HT.getcookies!(jar, "https", "api.example.com", "/")
    names_subdomain = [c.name for c in cookies_subdomain]
    @test "domainwide" in names_subdomain
    @test !("root" in names_subdomain)
    @test !("auto" in names_subdomain)

    delete_headers = _set_cookie_headers("root=gone; Path=/; Max-Age=-1")
    HT.setcookies!(jar, "https", "example.com", "/docs/index", delete_headers)
    @test !("root" in [c.name for c in HT.getcookies!(jar, "https", "example.com", "/docs/page")])

    expired_headers = _set_cookie_headers("expired=old; Path=/; Expires=Wed, 23-Nov-2011 01:05:03 GMT")
    HT.setcookies!(jar, "https", "example.com", "/docs/index", expired_headers)
    @test !("expired" in [c.name for c in HT.getcookies!(jar, "https", "example.com", "/docs/page")])
end
