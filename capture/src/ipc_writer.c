/*
 * ipc_writer.c — Unix domain socket IPC, ring buffer, background sender.
 *
 * The packet callback thread enqueues via ipc_writer_enqueue() — lock-free
 * write to the ring with an atomic index update. The sender thread drains
 * the ring and writes to the socket; it reconnects if the socket drops.
 *
 * Ring buffer layout: head = next write position (producer), tail = next
 * read position (consumer). Full condition: (head - tail) == capacity.
 * Empty condition: head == tail. Single producer, single consumer — no CAS
 * needed, only compiler barriers to prevent reordering.
 */

#include "ipc_writer.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>

/* ── Ring buffer ─────────────────────────────────────────────────────────── */

static flow_record_t  ring[IPC_RING_CAPACITY];

// head: written by producer (packet callback), read by consumer (sender thread)
// tail: written by consumer, read by producer
static _Atomic uint32_t ring_head = 0;
static _Atomic uint32_t ring_tail = 0;

static _Atomic int      running   = 1;   // set to 0 by ipc_writer_shutdown()

static uint64_t drops = 0;               // flows dropped due to full ring

/* ── Socket ──────────────────────────────────────────────────────────────── */

static int sock_fd = -1;

static int connect_socket(void)
{
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[ipc] socket()");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    sock_fd = fd;
    fprintf(stderr, "[ipc] connected to %s\n", IPC_SOCKET_PATH);
    return 0;
}

/* Write exactly n bytes; returns 0 on success, -1 on error/disconnect. */
static int write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* ── Sender thread ────────────────────────────────────────────────────────── */

static void *sender_thread(void *arg)
{
    (void)arg;
    uint32_t payload_len = sizeof(flow_record_t);

    while (atomic_load(&running) || atomic_load(&ring_head) != atomic_load(&ring_tail)) {
        // Reconnect loop — retry every 100ms until Python server is up
        while (sock_fd < 0 && atomic_load(&running)) {
            if (connect_socket() < 0)
                usleep(100000);   // 100ms — short enough to not miss flows
        }

        uint32_t head = atomic_load(&ring_head);
        uint32_t tail = atomic_load(&ring_tail);

        if (head == tail) {
            // Ring empty — yield without spinning at 100% CPU
            usleep(1000);   // 1ms
            continue;
        }

        // Send the flow at tail position
        uint32_t slot = tail & (IPC_RING_CAPACITY - 1);
        const flow_record_t *flow = &ring[slot];

        // Write length prefix then struct — two writes is fine here since
        // we are not in the hot capture path
        int err = write_all(sock_fd, &payload_len, sizeof(payload_len));
        if (err == 0)
            err = write_all(sock_fd, flow, sizeof(flow_record_t));

        if (err < 0) {
            fprintf(stderr, "[ipc] send error, reconnecting...\n");
            close(sock_fd);
            sock_fd = -1;
            // Do not advance tail — retry this flow after reconnect
            continue;
        }

        atomic_store(&ring_tail, tail + 1);
    }

    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void ipc_writer_init(void)
{
    atomic_store(&ring_head, 0);
    atomic_store(&ring_tail, 0);
    atomic_store(&running, 1);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, sender_thread, NULL);
    pthread_attr_destroy(&attr);
}

void ipc_writer_enqueue(const flow_record_t *flow)
{
    uint32_t head = atomic_load(&ring_head);
    uint32_t tail = atomic_load(&ring_tail);

    if (head - tail >= IPC_RING_CAPACITY) {
        // Ring full — drop oldest by advancing tail
        atomic_store(&ring_tail, tail + 1);
        drops++;
        if (drops % 100 == 0)
            fprintf(stderr, "[ipc] WARNING: ring buffer full, %llu flows dropped\n",
                    (unsigned long long)drops);
    }

    uint32_t slot = head & (IPC_RING_CAPACITY - 1);
    // Copy before updating head — ensures the sender sees a complete record
    ring[slot] = *flow;
    // Atomic store with release semantics so the write above is visible
    // to the sender thread before it reads the updated head
    atomic_store_explicit(&ring_head, head + 1, memory_order_release);
}

void ipc_writer_shutdown(void)
{
    atomic_store(&running, 0);
}
