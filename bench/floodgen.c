/* floodgen.c — a small multi-threaded UDP packet generator used to put load
 * on the XDP load balancer for the demo.
 *
 * It is deliberately simple (plain connected UDP sockets + sendmmsg batching,
 * one thread per core) rather than a full kernel-bypass tool like DPDK/pktgen
 * or an AF_XDP zero-copy sender. That's an honest trade-off: this can drive
 * enough traffic to *watch the LB's counters climb* and prove the data path
 * works, but the multi-tens-of-millions-of-pps regime that XDP/eBPF makes
 * possible on the *receive* side (which is what this whole project is
 * demonstrating) generally needs a generator of comparable sophistication on
 * the *send* side too -- see the README for what a from-the-same-toolbox
 * AF_XDP sender would look like.
 *
 * Each thread opens N_SOCKS_PER_THREAD connected UDP sockets (so the kernel
 * assigns each a distinct ephemeral source port, giving many independent
 * flows to exercise the LB's consistent-hash spread across backends) and
 * blasts fixed-size datagrams at them with sendmmsg() batches until the
 * requested duration elapses.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define N_SOCKS_PER_THREAD 32
#define BATCH 256
#define PAYLOAD_LEN 64

static atomic_ulong g_sent = 0;
static volatile sig_atomic_t g_stop = 0;

struct thread_arg {
    struct sockaddr_in dst;
};

static void on_alarm(int sig) {
    (void)sig;
    g_stop = 1;
}

static void *worker(void *arg_) {
    struct thread_arg *arg = arg_;
    int socks[N_SOCKS_PER_THREAD];

    for (int i = 0; i < N_SOCKS_PER_THREAD; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); exit(1); }
        if (connect(fd, (struct sockaddr *)&arg->dst, sizeof(arg->dst)) != 0) {
            perror("connect");
            exit(1);
        }
        socks[i] = fd;
    }

    char payload[PAYLOAD_LEN];
    memset(payload, 'A', sizeof(payload));

    struct iovec iov[BATCH];
    struct mmsghdr msgs[BATCH];
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = payload;
        iov[i].iov_len = sizeof(payload);
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    unsigned long local_sent = 0;
    int sock_idx = 0;
    while (!g_stop) {
        int fd = socks[sock_idx];
        sock_idx = (sock_idx + 1) % N_SOCKS_PER_THREAD;
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n > 0) local_sent += (unsigned long)n;
        /* Ignore transient send errors (e.g. ENOBUFS under heavy load) -- a
         * flood generator's job is to keep pushing, not to guarantee
         * delivery. */
    }

    atomic_fetch_add(&g_sent, local_sent);
    for (int i = 0; i < N_SOCKS_PER_THREAD; i++) close(socks[i]);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <dst_ip> <dst_port> <duration_sec> [threads]\n", argv[0]);
        return 1;
    }
    const char *dst_ip = argv[1];
    int dst_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    long nthreads = argc > 4 ? atol(argv[4]) : sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 1;

    struct thread_arg arg;
    memset(&arg.dst, 0, sizeof(arg.dst));
    arg.dst.sin_family = AF_INET;
    arg.dst.sin_port = htons((uint16_t)dst_port);
    if (inet_pton(AF_INET, dst_ip, &arg.dst.sin_addr) != 1) {
        fprintf(stderr, "invalid destination ip: %s\n", dst_ip);
        return 1;
    }

    fprintf(stderr, "floodgen: %ld threads x %d sockets -> %s:%d for %ds\n",
            nthreads, N_SOCKS_PER_THREAD, dst_ip, dst_port, duration);

    signal(SIGALRM, on_alarm);
    alarm((unsigned)duration);

    pthread_t *tids = calloc((size_t)nthreads, sizeof(pthread_t));
    if (!tids) { perror("calloc"); return 1; }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < nthreads; i++) {
        int err = pthread_create(&tids[i], NULL, worker, &arg);
        if (err) { fprintf(stderr, "pthread_create: %s\n", strerror(err)); return 1; }
    }
    for (long i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    unsigned long total = atomic_load(&g_sent);
    fprintf(stderr, "floodgen: sent %lu packets in %.2fs = %.0f pps\n",
            total, elapsed, (double)total / elapsed);

    free(tids);
    return 0;
}
