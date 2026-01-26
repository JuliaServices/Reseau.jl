@enumx CliOptionArg::UInt8 begin
    NO_ARGUMENT = 0
    REQUIRED_ARGUMENT = 1
    OPTIONAL_ARGUMENT = 2
end

@enumx CliStepKind::UInt8 begin
    END = 0
    ERROR = 1
    POSITIONAL = 2
    OPTION = 3
end

const cli_option_arg = CliOptionArg.T
const cli_step_kind = CliStepKind.T

Base.@kwdef struct CliOption
    name::String
    short::Union{Char,Nothing} = nothing
    arg::cli_option_arg = CliOptionArg.NO_ARGUMENT
end

struct CliStep
    kind::cli_step_kind
    option::Union{CliOption,Nothing}
    value::Union{String,Nothing}
end

mutable struct CliParseState
    optind::Int
end

CliParseState() = CliParseState(1)

function cli_reset_state!(state::CliParseState)
    state.optind = 1
    return nothing
end

@inline function _find_long_option(options::Vector{CliOption}, name::AbstractString)
    for opt in options
        if opt.name == name
            return opt
        end
    end
    return nothing
end

@inline function _find_short_option(options::Vector{CliOption}, short::Char)
    for opt in options
        if opt.short === short
            return opt
        end
    end
    return nothing
end

function _resolve_option_value!(state::CliParseState, opt::CliOption, args::Vector{String})
    if opt.arg == CliOptionArg.NO_ARGUMENT
        return CliStep(CliStepKind.OPTION, opt, nothing)
    end

    if state.optind > length(args)
        if opt.arg == CliOptionArg.OPTIONAL_ARGUMENT
            return CliStep(CliStepKind.OPTION, opt, nothing)
        end
        return CliStep(CliStepKind.ERROR, opt, nothing)
    end

    value = args[state.optind]
    if opt.arg == CliOptionArg.OPTIONAL_ARGUMENT && startswith(value, "-")
        return CliStep(CliStepKind.OPTION, opt, nothing)
    end

    state.optind += 1
    return CliStep(CliStepKind.OPTION, opt, value)
end

function cli_getopt_long!(state::CliParseState, args::Vector{String}, options::Vector{CliOption})
    if state.optind > length(args)
        return CliStep(CliStepKind.END, nothing, nothing)
    end

    arg = args[state.optind]
    state.optind += 1

    if startswith(arg, "--")
        name = arg[3:end]
        if isempty(name)
            return CliStep(CliStepKind.ERROR, nothing, arg)
        end
        opt = _find_long_option(options, name)
        return opt === nothing ? CliStep(CliStepKind.ERROR, nothing, arg) : _resolve_option_value!(state, opt, args)
    elseif startswith(arg, "-") && length(arg) > 1
        opt = _find_short_option(options, arg[2])
        return opt === nothing ? CliStep(CliStepKind.ERROR, nothing, arg) : _resolve_option_value!(state, opt, args)
    end

    return CliStep(CliStepKind.POSITIONAL, nothing, arg)
end

struct CliSubcommand{F}
    name::String
    run::F
end

function cli_dispatch_on_subcommand(args::Vector{String}, dispatch_table::Vector{CliSubcommand})
    length(args) < 2 && return raise_error(ERROR_INVALID_ARGUMENT)
    cmd_name = args[2]
    for entry in dispatch_table
        if lowercase(entry.name) == lowercase(cmd_name)
            return entry.run(args[2:end])
        end
    end
    return raise_error(ERROR_UNIMPLEMENTED)
end
