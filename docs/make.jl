using Documenter, Reseau

makedocs(
    sitename = "Reseau.jl",
    format = Documenter.HTML(),
    modules = [Reseau],
    pages = [
        "Home" => "index.md",
        "TCP and Resolution" => "tcp.md",
        "TLS" => "tls.md",
        "Sockets Migration Guide" => "migrate-sockets.md",
        "API Reference" => "reference.md",
    ],
    clean = true,
    checkdocs = :none,
)

if get(ENV, "DEPLOY_DOCS", "false") == "true"
    deploydocs(
        repo = "github.com/JuliaWeb/Reseau.jl.git",
        push_preview = true,
    )
end
