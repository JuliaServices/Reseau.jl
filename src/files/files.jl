# Implementation of `Reseau.Files`.

export
    # Core handle type
    FileHandle,
    # Submodules
    Async,
    Watching,
    Locking,
    Backend,
    # Flag + mode constants (Base.Filesystem parity)
    JL_O_RDONLY,
    JL_O_WRONLY,
    JL_O_RDWR,
    JL_O_APPEND,
    JL_O_CREAT,
    JL_O_EXCL,
    JL_O_TRUNC,
    JL_O_NONBLOCK,
    JL_O_CLOEXEC,
    S_IFDIR,
    S_IFCHR,
    S_IFBLK,
    S_IFREG,
    S_IFIFO,
    S_IFLNK,
    S_IFSOCK,
    S_IFMT,
    S_ISUID,
    S_ISGID,
    S_ENFMT,
    S_ISVTX,
    S_IRUSR,
    S_IWUSR,
    S_IXUSR,
    S_IRWXU,
    S_IRGRP,
    S_IWGRP,
    S_IXGRP,
    S_IRWXG,
    S_IROTH,
    S_IWOTH,
    S_IXOTH,
    S_IRWXO

include("constants.jl")
include("filehandle.jl")
include("stat.jl")
include("fsops.jl")
include("backend.jl")

# Higher-level surfaces (async, watching, locking).
include("async.jl")
include("watching.jl")
include("locking.jl")
