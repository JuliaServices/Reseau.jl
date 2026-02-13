module ReseauS2NExt

using Reseau
import s2n_tls_jll

function __init__()
    if s2n_tls_jll.is_available() && hasproperty(s2n_tls_jll, :libs2n)
        # JLLWrappers library products export a String path (e.g. libs2n), and also keep the
        # dlopen()'d handle (e.g. libs2n_handle). We prefer the handle so we can dlsym() safely.
        if hasproperty(s2n_tls_jll, :libs2n_handle) && s2n_tls_jll.libs2n_handle != C_NULL
            lib = s2n_tls_jll.libs2n_handle
        else
            lib = s2n_tls_jll.libs2n
        end

        # Keep behavior tolerant to module-structure drift between versions.
        if isdefined(Reseau, :_register_s2n_lib!)
            Reseau._register_s2n_lib!(lib)
        elseif isdefined(Reseau, :Sockets) && isdefined(Reseau.Sockets, :_register_s2n_lib!)
            Reseau.Sockets._register_s2n_lib!(lib)
        end
    end
    return nothing
end

end # module ReseauS2NExt
