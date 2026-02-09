# Constants for Base.Filesystem parity.
#
# For v1, we alias Base's definitions so downstream code can use the familiar names.
# This does *not* call libuv; these are compile-time constants.

# Open flags (libuv-style JL_O_*), as exported by Base.Filesystem.
const JL_O_RDONLY = Base.Filesystem.JL_O_RDONLY
const JL_O_WRONLY = Base.Filesystem.JL_O_WRONLY
const JL_O_RDWR = Base.Filesystem.JL_O_RDWR
const JL_O_APPEND = Base.Filesystem.JL_O_APPEND
const JL_O_CREAT = Base.Filesystem.JL_O_CREAT
const JL_O_EXCL = Base.Filesystem.JL_O_EXCL
const JL_O_TRUNC = Base.Filesystem.JL_O_TRUNC
const JL_O_NONBLOCK = Base.Filesystem.JL_O_NONBLOCK
const JL_O_CLOEXEC = Base.Filesystem.JL_O_CLOEXEC

# Mode bits (POSIX-style), as exported by Base.Filesystem.
const S_IFDIR = Base.Filesystem.S_IFDIR
const S_IFCHR = Base.Filesystem.S_IFCHR
const S_IFBLK = Base.Filesystem.S_IFBLK
const S_IFREG = Base.Filesystem.S_IFREG
const S_IFIFO = Base.Filesystem.S_IFIFO
const S_IFLNK = Base.Filesystem.S_IFLNK
const S_IFSOCK = Base.Filesystem.S_IFSOCK
const S_IFMT = Base.Filesystem.S_IFMT

const S_ISUID = Base.Filesystem.S_ISUID
const S_ISGID = Base.Filesystem.S_ISGID
const S_ENFMT = Base.Filesystem.S_ENFMT
const S_ISVTX = Base.Filesystem.S_ISVTX

const S_IRUSR = Base.Filesystem.S_IRUSR
const S_IWUSR = Base.Filesystem.S_IWUSR
const S_IXUSR = Base.Filesystem.S_IXUSR
const S_IRWXU = Base.Filesystem.S_IRWXU
const S_IRGRP = Base.Filesystem.S_IRGRP
const S_IWGRP = Base.Filesystem.S_IWGRP
const S_IXGRP = Base.Filesystem.S_IXGRP
const S_IRWXG = Base.Filesystem.S_IRWXG
const S_IROTH = Base.Filesystem.S_IROTH
const S_IWOTH = Base.Filesystem.S_IWOTH
const S_IXOTH = Base.Filesystem.S_IXOTH
const S_IRWXO = Base.Filesystem.S_IRWXO

