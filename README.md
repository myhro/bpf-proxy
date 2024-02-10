BPF Proxy
=========

This is a reimplementation of the [jsitnicki/ebpf-summit-2020][ebpf-summit-2020] echo dispatcher proxy with modern BPF features. It includes many of the improvements made to the ecosystem in the past 3+ years, like:

- [BTF, CO-RE and libbpf][btf].
- [BPF skeleton][skel].
- [Updated map syntax][libbpf-maps].

Plus:

- Single binary.
- libbpf helpers instead of `bpf()` syscalls.
- Include `sys/pidfd.h` instead of custom syscall wrappers.
- No need for `bpftool`, avoiding hand-editing maps and custom pinning.

## Dependencies

    $ sudo apt install build-essential clang libbpf-dev

## Usage

Start the proxy with `./proxy [pid] [fd] [port [port...]]`, replacing the arguments with the respective process ID, file descriptor and port numbers:

```
$ sudo ./proxy 7738 3 77 777
pid: 7738, fd: 3
pid_fd: 3, sock_fd: 4
port: 77
port: 777
```

On another terminal:

```
$ nc -vz 127.0.0.1 77
Connection to 127.0.0.1 77 port [tcp/*] succeeded!
$ nc -vz 127.0.0.1 777
Connection to 127.0.0.1 777 port [tcp/moira-update] succeeded!
```


[btf]: https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html
[ebpf-summit-2020]: https://github.com/jsitnicki/ebpf-summit-2020
[libbpf-maps]: https://github.com/libbpf/libbpf/wiki/Libbpf:-the-road-to-v1.0#drop-support-for-legacy-bpf-map-declaration-syntax
[skel]: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-object-skeleton-file
