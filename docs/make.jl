using Documenter, Reseau

DocMeta.setdocmeta!(Reseau, :DocTestSetup, :(using Reseau); recursive = true)

makedocs(
    sitename = "Reseau.jl",
    modules = [Reseau],
    format = Documenter.HTML(
        prettyurls = true,
        canonical = "https://juliaservices.github.io/Reseau.jl/stable",
        collapselevel = 2,
        edit_link = "main",
        description = "Pure-Julia TCP and TLS transport stack with deadline-aware I/O, host-aware dialing, and Go-inspired networking architecture.",
    ),
    pages = [
        "Home" => "index.md",
        "TCP" => "tcp.md",
        "TLS" => "tls.md",
        "Name Resolution" => "resolution.md",
        "Sockets Migration Guide" => "migrate-sockets.md",
        "API Reference" => "reference.md",
    ],
    pagesonly = true,
    checkdocs = :exports,
)

deploydocs(
    repo = "github.com/JuliaServices/Reseau.jl.git",
    devbranch = "main",
    push_preview = true,
)
