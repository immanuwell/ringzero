//! Single translate-c boundary for the whole project. Everything else in
//! src/ imports `c.zig` rather than calling @cImport itself, so there's only
//! ever one C type universe to reason about.
pub const c = @cImport({
    @cInclude("stdint.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("net/if.h");
    @cInclude("arpa/inet.h");
    @cInclude("linux/if_link.h");
    @cInclude("bpf/libbpf.h");
    @cInclude("bpf/bpf.h");
    @cInclude("common.h");
});
