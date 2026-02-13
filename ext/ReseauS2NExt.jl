module ReseauS2NExt

using Reseau
import s2n_tls_jll

function __init__()
    if s2n_tls_jll.is_available() && hasproperty(s2n_tls_jll, :libs2n)
        # JLLWrappers library products export a String path (e.g. libs2n), and also keep the
        # dlopen()'d handle (e.g. libs2n_handle). We prefer the handle so we can dlsym() safely.
        if hasproperty(s2n_tls_jll, :libs2n_handle) && s2n_tls_jll.libs2n_handle != C_NULL
            Reseau.Sockets._register_s2n_lib!(s2n_tls_jll.libs2n_handle)
        else
            Reseau.Sockets._register_s2n_lib!(s2n_tls_jll.libs2n)
        end
    end
    return nothing
end

end # module ReseauS2NExt
