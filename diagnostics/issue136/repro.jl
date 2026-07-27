using InteractiveUtils
using Pkg

const DIAGNOSTIC_REV = get(
    ENV,
    "RESEAU_DIAGNOSTIC_REV",
    "diagnostics/windows-precompile-136",
)

println("RESEAU_136_REPRO_BEGIN")
println("revision = ", DIAGNOSTIC_REV)
println("trace = ", get(ENV, "RESEAU_PRECOMPILE_TRACE", ""))
versioninfo(verbose = true)
flush(stdout)

# Match the issue reproducer while ensuring the diagnostic branch, rather than
# main or the mitigation PR, supplies the package source.
Pkg.activate(temp = true)
Pkg.add(
    url = "https://github.com/JuliaServices/Reseau.jl",
    rev = DIAGNOSTIC_REV,
)

println("RESEAU_136_REPRO_DONE")
flush(stdout)
