struct NoopShutdownCallback end

@inline (::NoopShutdownCallback)() = nothing

struct shutdown_callback_options{F}
    shutdown_callback_fn::F
end

shutdown_callback_options() = shutdown_callback_options(NoopShutdownCallback())
