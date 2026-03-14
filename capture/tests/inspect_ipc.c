/*
 * inspect_ipc.c — debug tool: binds the IPC socket as server, reads flow
 * records from the C capture engine, and prints each as a JSON summary.
 *
 * Run alongside capture_engine for integration testing:
 *   ./inspect_ipc &
 *   ./capture_engine -i eth0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "flow_types.h"

#define SOCKET_PATH  "/tmp/ids_ipc/flows.sock"
#define BACKLOG      4

static volatile int keep_running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr a = { .s_addr = htonl(ip) };
    strncpy(buf, inet_ntoa(a), len - 1);
    buf[len - 1] = '\0';
}

/* Read exactly n bytes from fd; returns 0 on success, -1 on EOF/error. */
static int read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static void print_flow_json(const flow_record_t *f, uint64_t seq)
{
    char src[20], dst[20];
    ip_to_str(f->key.src_ip, src, sizeof(src));
    ip_to_str(f->key.dst_ip, dst, sizeof(dst));

    printf("{\n");
    printf("  \"seq\":            %llu,\n",  (unsigned long long)seq);
    printf("  \"proto\":          %u,\n",    f->key.protocol);
    printf("  \"src\":            \"%s:%u\",\n", src, f->key.src_port);
    printf("  \"dst\":            \"%s:%u\",\n", dst, f->key.dst_port);
    printf("  \"flow_duration_s\":%.6f,\n",  f->flow_duration_s);
    printf("  \"tot_pkts\":       %u,\n",    f->tot_pkts);
    printf("  \"tot_fwd_pkts\":   %u,\n",    f->tot_fwd_pkts);
    printf("  \"tot_bwd_pkts\":   %u,\n",    f->tot_bwd_pkts);
    printf("  \"tot_fwd_bytes\":  %llu,\n",  (unsigned long long)f->tot_fwd_bytes);
    printf("  \"tot_bwd_bytes\":  %llu,\n",  (unsigned long long)f->tot_bwd_bytes);
    printf("  \"pkt_len_mean\":   %.4f,\n",  f->pkt_len_mean);
    printf("  \"pkt_len_std\":    %.4f,\n",  f->pkt_len_std);
    printf("  \"bwd_pkt_len_mean\":%.4f,\n", f->bwd_pkt_len_mean);
    printf("  \"bwd_pkt_len_std\": %.4f,\n", f->bwd_pkt_len_std);
    printf("  \"bwd_pkt_len_max\": %u,\n",   f->bwd_pkt_len_max);
    printf("  \"bwd_pkts_per_s\": %.4f,\n",  f->bwd_pkts_per_sec);
    printf("  \"syn_flag_cnt\":   %u,\n",    f->syn_flag_cnt);
    printf("  \"fin_flag_cnt\":   %u,\n",    f->fin_flag_cnt);
    printf("  \"rst_flag_cnt\":   %u,\n",    f->rst_flag_cnt);
    printf("  \"psh_flag_cnt\":   %u,\n",    f->psh_flag_cnt);
    printf("  \"ack_flag_cnt\":   %u,\n",    f->ack_flag_cnt);
    printf("  \"urg_flag_cnt\":   %u,\n",    f->urg_flag_cnt);
    printf("  \"init_fwd_win\":   %u,\n",    f->init_fwd_win_bytes);
    printf("  \"fwd_seg_min\":    %u,\n",    f->fwd_seg_size_min);
    printf("  \"fwd_act_data\":   %u,\n",    f->fwd_act_data_pkts);
    printf("  \"fwd_pkt_len_max\":%u,\n",    f->fwd_pkt_len_max);
    printf("  \"flow_iat_mean\":  %.2f,\n",  f->flow_iat_mean);
    printf("  \"fwd_iat_std\":    %.2f,\n",  f->fwd_iat_std);
    printf("  \"sizeof_struct\":  %zu\n",    sizeof(flow_record_t));
    printf("}\n");
    fflush(stdout);
}

static void handle_client(int client_fd)
{
    uint64_t seq = 0;
    flow_record_t flow;
    uint32_t payload_len;

    while (keep_running) {
        // Read length prefix
        if (read_all(client_fd, &payload_len, sizeof(payload_len)) < 0)
            break;

        if (payload_len != sizeof(flow_record_t)) {
            fprintf(stderr, "[inspect] ERROR: unexpected payload_len=%u expected=%zu\n",
                    payload_len, sizeof(flow_record_t));
            // Read and discard the mismatched bytes to stay in sync
            uint8_t discard[4096];
            uint32_t remaining = payload_len;
            while (remaining > 0) {
                uint32_t chunk = remaining < sizeof(discard) ? remaining : (uint32_t)sizeof(discard);
                if (read_all(client_fd, discard, chunk) < 0) break;
                remaining -= chunk;
            }
            continue;
        }

        if (read_all(client_fd, &flow, sizeof(flow_record_t)) < 0)
            break;

        print_flow_json(&flow, seq++);
    }
}

int main(void)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    // Print the struct size so the Python side can verify alignment
    printf("[inspect] sizeof(flow_record_t) = %zu bytes\n", sizeof(flow_record_t));
    fflush(stdout);

    // Remove stale socket file if present
    unlink(SOCKET_PATH);

    // Ensure directory exists
    mkdir("/tmp/ids_ipc", 0700);

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen"); return 1;
    }

    fprintf(stderr, "[inspect] listening on %s\n", SOCKET_PATH);

    while (keep_running) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) {
            if (keep_running) perror("accept");
            break;
        }
        fprintf(stderr, "[inspect] client connected\n");
        handle_client(client);
        close(client);
        fprintf(stderr, "[inspect] client disconnected\n");
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}
