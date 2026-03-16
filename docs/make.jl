using Documenter, Reseau

makedocs(
    sitename = "Reseau.jl",
    format = Documenter.HTML(),
    modules = [Reseau],
    pages = [
        "Home" => "index.md",
        "TCP" => "tcp.md",
        "TLS" => "tls.md",
        "Sockets Migration Guide" => "migrate-sockets.md",
        "API Reference" => "reference.md",
    ],
    clean = true,
    checkdocs = :none,
)

deploydocs(
    repo = "github.com/JuliaServices/Reseau.jl.git",
    push_preview = true,
)
