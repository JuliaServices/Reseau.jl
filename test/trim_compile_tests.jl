using Test
import JuliaC

@testset "Trim compile" begin
    project_path = normpath(joinpath(@__DIR__, ".."))
    script_path = joinpath(project_path, "trim", "echo_trim_safe.jl")
    @test isfile(script_path)

    mktempdir() do tmpdir
        cd(tmpdir) do
            output_name = "echo_trim_safe"
            JuliaC.main([
                "--output-exe", output_name,
                "--project=$(project_path)",
                "--experimental",
                "--trim=safe",
                script_path,
            ])

            output_path = Sys.iswindows() ? "$(output_name).exe" : output_name
            @test isfile(output_path)
        end
    end
end
