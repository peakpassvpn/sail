// Counts socket I/O syscalls and bytes per call. Load with
//   DYLD_INSERT_LIBRARIES=syscount.dylib SYSCOUNT_OUT=/path/stats.txt <program>
// Counters are rewritten to SYSCOUNT_OUT every 200 ms, so the file always
// holds the latest totals even if the program is killed.
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>

enum { S_SEND, S_SENDTO, S_SENDMSG, S_WRITE, S_WRITEV, S_RECV, S_RECVFROM, S_RECVMSG, S_READ, S_READV, S_N };
static const char *names[S_N] = {"send", "sendto", "sendmsg", "write", "writev", "recv", "recvfrom", "recvmsg", "read", "readv"};
static _Atomic unsigned long calls[S_N], bytes[S_N], again[S_N];

static int is_sock(int fd) { struct stat st; return fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode); }
static void count(int k, int fd, ssize_t r) {
    if (!is_sock(fd)) return;
    calls[k]++;
    if (r > 0) bytes[k] += (unsigned long)r; else if (r < 0) again[k]++;
}

#define INTERPOSE(n, o) __attribute__((used)) static struct { const void *r, *o; } _i_##o __attribute__((section("__DATA,__interpose"))) = { (const void *)n, (const void *)o };

static ssize_t my_send(int fd, const void *b, size_t l, int f) { ssize_t r = send(fd, b, l, f); count(S_SEND, fd, r); return r; }
static ssize_t my_sendto(int fd, const void *b, size_t l, int f, const struct sockaddr *a, socklen_t al) { ssize_t r = sendto(fd, b, l, f, a, al); count(S_SENDTO, fd, r); return r; }
static ssize_t my_sendmsg(int fd, const struct msghdr *m, int f) { ssize_t r = sendmsg(fd, m, f); count(S_SENDMSG, fd, r); return r; }
static ssize_t my_write(int fd, const void *b, size_t l) { ssize_t r = write(fd, b, l); count(S_WRITE, fd, r); return r; }
static ssize_t my_writev(int fd, const struct iovec *v, int n) { ssize_t r = writev(fd, v, n); count(S_WRITEV, fd, r); return r; }
static ssize_t my_recv(int fd, void *b, size_t l, int f) { ssize_t r = recv(fd, b, l, f); count(S_RECV, fd, r); return r; }
static ssize_t my_recvfrom(int fd, void *b, size_t l, int f, struct sockaddr *a, socklen_t *al) { ssize_t r = recvfrom(fd, b, l, f, a, al); count(S_RECVFROM, fd, r); return r; }
static ssize_t my_recvmsg(int fd, struct msghdr *m, int f) { ssize_t r = recvmsg(fd, m, f); count(S_RECVMSG, fd, r); return r; }
static ssize_t my_read(int fd, void *b, size_t l) { ssize_t r = read(fd, b, l); count(S_READ, fd, r); return r; }
static ssize_t my_readv(int fd, const struct iovec *v, int n) { ssize_t r = readv(fd, v, n); count(S_READV, fd, r); return r; }
INTERPOSE(my_send, send) INTERPOSE(my_sendto, sendto) INTERPOSE(my_sendmsg, sendmsg)
INTERPOSE(my_write, write) INTERPOSE(my_writev, writev)
INTERPOSE(my_recv, recv) INTERPOSE(my_recvfrom, recvfrom) INTERPOSE(my_recvmsg, recvmsg)
INTERPOSE(my_read, read) INTERPOSE(my_readv, readv)

static void *dumper(void *path) {
    char tmp[1024]; snprintf(tmp, sizeof tmp, "%s.tmp", (char *)path);
    for (;;) {
        usleep(200000);
        FILE *f = fopen(tmp, "w"); if (!f) continue;
        for (int k = 0; k < S_N; k++)
            if (calls[k]) fprintf(f, "%s %lu %lu %lu\n", names[k], calls[k], bytes[k], again[k]);
        fclose(f); rename(tmp, path);
    }
    return NULL;
}
__attribute__((constructor)) static void init(void) {
    const char *out = getenv("SYSCOUNT_OUT");
    if (!out) return;
    pthread_t t; pthread_create(&t, NULL, dumper, strdup(out)); pthread_detach(t);
}
