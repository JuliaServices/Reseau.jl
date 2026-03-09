using Test
using Reseau
using Base64

const HT = Reseau.HTTP

@testset "HTTP proxy explicit config parsing" begin
    proxy = HT.ProxyURL("http://user:pass@proxy.local:8080")
    @test proxy.url == "http://proxy.local:8080/"
    @test !proxy.secure
    @test proxy.address == "proxy.local:8080"
    @test proxy.authorization == "Basic " * base64encode("user:pass")

    default_scheme = HT.ProxyURL("proxy.local:9000")
    @test default_scheme.url == "http://proxy.local:9000/"
    @test !default_scheme.secure
    @test default_scheme.address == "proxy.local:9000"
end

@testset "HTTP proxy no_proxy matching" begin
    matcher = HT.NoProxy("example.com,.internal.local,127.0.0.1,10.0.0.0/8,[::1],*.svc.local,1.2.3.4:8443")
    @test HT._matches_no_proxy(matcher, "example.com", 80)
    @test HT._matches_no_proxy(matcher, "api.example.com", 80)
    @test HT._matches_no_proxy(matcher, "foo.internal.local", 80)
    @test !HT._matches_no_proxy(matcher, "internal.local", 80)
    @test HT._matches_no_proxy(matcher, "127.0.0.1", 80)
    @test HT._matches_no_proxy(matcher, "10.2.3.4", 443)
    @test HT._matches_no_proxy(matcher, "::1", 443)
    @test HT._matches_no_proxy(matcher, "db.svc.local", 443)
    @test HT._matches_no_proxy(matcher, "1.2.3.4", 8443)
    @test !HT._matches_no_proxy(matcher, "1.2.3.4", 443)
    @test !HT._matches_no_proxy(matcher, "public.example.net", 80)

    all_match = HT.NoProxy("*")
    @test HT._matches_no_proxy(all_match, "anything.example", 80)
end

@testset "HTTP proxy env selection and all_proxy fallback" begin
    selector = withenv(
            "HTTP_PROXY" => "http://user:pass@http-proxy.local:8080",
            "HTTPS_PROXY" => "https://https-proxy.local:8443",
            "ALL_PROXY" => "http://fallback-proxy.local:3128",
            "NO_PROXY" => "skip.local,.bypass.local,192.168.0.0/16",
        ) do
        HT.ProxyFromEnvironment()
    end
    http_proxy = HT._proxy_for(selector, false, "public.local", 80)
    @test http_proxy !== nothing
    @test (http_proxy::HT.ProxyConfig).address == "http-proxy.local:8080"
    @test (http_proxy::HT.ProxyConfig).authorization == "Basic " * base64encode("user:pass")

    https_proxy = HT._proxy_for(selector, true, "secure.local", 443)
    @test https_proxy !== nothing
    @test (https_proxy::HT.ProxyConfig).secure
    @test (https_proxy::HT.ProxyConfig).address == "https-proxy.local:8443"

    bypass = HT._proxy_for(selector, true, "api.bypass.local", 443)
    @test bypass === nothing

    selector_fallback = withenv(
            "HTTP_PROXY" => nothing,
            "http_proxy" => nothing,
            "HTTPS_PROXY" => nothing,
            "https_proxy" => nothing,
            "ALL_PROXY" => "http://fallback-proxy.local:3128",
            "NO_PROXY" => nothing,
            "no_proxy" => nothing,
        ) do
        HT.ProxyFromEnvironment()
    end
    fallback = HT._proxy_for(selector_fallback, false, "origin.local", 80)
    @test fallback !== nothing
    @test (fallback::HT.ProxyConfig).address == "fallback-proxy.local:3128"
end

@testset "HTTP proxy planning chooses direct, forward, and tunnel modes" begin
    direct = HT._proxy_plan(nothing, false, "origin.local:80")
    @test direct.mode == HT._ProxyPlanMode.DIRECT
    @test direct.proxy === nothing

    proxy = HT.ProxyURL("http://proxy.local:8080")
    forward = HT._proxy_plan(proxy, false, "origin.local:80")
    @test forward.mode == HT._ProxyPlanMode.HTTP_FORWARD
    @test forward.proxy !== nothing
    @test forward.first_hop_key == "http://proxy.local:8080/|http://origin.local:80"

    tunnel = HT._proxy_plan(proxy, true, "origin.local:443")
    @test tunnel.mode == HT._ProxyPlanMode.HTTP_TUNNEL
    @test tunnel.first_hop_key == "http://proxy.local:8080/|https://origin.local:443"
end
