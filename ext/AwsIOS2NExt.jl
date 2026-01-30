module AwsIOS2NExt

using AwsIO
import s2n_tls_jll

function __init__()
    if s2n_tls_jll.is_available() && hasproperty(s2n_tls_jll, :libs2n)
        AwsIO._register_s2n_lib!(s2n_tls_jll.libs2n)
    end
    return nothing
end

end # module AwsIOS2NExt
