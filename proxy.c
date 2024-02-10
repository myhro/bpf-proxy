#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <unistd.h>
#include "proxy.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

int main(int argc, char **argv) {
    struct proxy_bpf *skel;
    int pid, fd;
    int err;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s [pid] [fd] [port [port...]]\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    fd = atoi(argv[2]);
    printf("pid: %d, fd: %d\n", pid, fd);

    int pid_fd = pidfd_open(pid, 0);
    if (pid_fd < 0) {
        fprintf(stderr, "pidfd_open error: %s\n", strerror(errno));
        return 1;
    }

    int sock_fd = pidfd_getfd(pid_fd, fd, 0);
    if (sock_fd < 0) {
        fprintf(stderr, "pidfd_getfd error: %s\n", strerror(errno));
        return 1;
    }

    printf("pid_fd: %d, sock_fd: %d\n", pid_fd, sock_fd);

    skel = proxy_bpf__open_and_load();
    if (skel == NULL) {
        fprintf(stderr, "failed to open and load BPF object\n");
        return 1;
    }

    __u32 zero = 0;
    __u64 sock = sock_fd;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.socket), &zero, &sock, BPF_ANY);
    if (err) {
        fprintf(stderr, "error updating socket map\n");
        return 1;
    }

    __u8 enabled = 1;
    for (int i = 3; i < argc; i++) {
        __u16 port = atoi(argv[i]);
        printf("port: %d\n", port);
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.ports), &port, &enabled, BPF_ANY);
        if (err) {
            fprintf(stderr, "error updating ports map\n");
            return 1;
        }
    }

    // Manually attach to the network namespace, given 'proxy_bpf__attach()'
    // won't do that automatically:
    int netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        fprintf(stderr, "/proc/self/ns/net error: %s\n", strerror(errno));
        return 1;
    }
    bpf_link_create(bpf_program__fd(skel->progs.proxy), netns_fd, BPF_SK_LOOKUP, NULL);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return 1;
    }

    while(!exiting) {
        sleep(1);
    }

    return 0;
}
