struct NoopShutdownCallback end

@inline (::NoopShutdownCallback)(_) = nothing

struct shutdown_callback_options{F, U}
    shutdown_callback_fn::F
    shutdown_callback_user_data::U
end

shutdown_callback_options() = shutdown_callback_options(NoopShutdownCallback(), nothing)
