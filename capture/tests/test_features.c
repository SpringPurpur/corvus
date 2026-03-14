/*
 * test_features.c — unit tests for AVX2 feature routines.
 *
 * No network access required. Tests AVX2 outputs against scalar reference
 * implementations. All tests must print PASS before the engine is used.
 *
 * Run: ./test_features
 * Expected exit code: 0 (all pass), non-zero on any failure.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

/* ── Declarations of AVX2 functions under test ───────────────────────────── */

extern void compute_pkt_len_stats_avx2(uint16_t *buf, uint32_t count,
                                        float *out_mean, float *out_std);

extern void count_tcp_flags_avx2(uint8_t *flags, uint32_t count,
                                  uint32_t *fin, uint32_t *syn, uint32_t *rst,
                                  uint32_t *psh, uint32_t *ack, uint32_t *urg);

/* ── Scalar reference implementations ───────────────────────────────────── */

static void scalar_pkt_len_stats(const uint16_t *buf, uint32_t count,
                                  float *out_mean, float *out_std)
{
    double sum = 0.0;
    for (uint32_t i = 0; i < count; i++)
        sum += buf[i];
    double mean = sum / count;

    double sq_sum = 0.0;
    for (uint32_t i = 0; i < count; i++) {
        double d = buf[i] - mean;
        sq_sum += d * d;
    }
    *out_mean = (float)mean;
    *out_std  = (float)sqrt(sq_sum / count);
}

static void scalar_count_flags(const uint8_t *flags, uint32_t count,
                                uint32_t *fin, uint32_t *syn, uint32_t *rst,
                                uint32_t *psh, uint32_t *ack, uint32_t *urg)
{
    *fin = *syn = *rst = *psh = *ack = *urg = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (flags[i] & 0x01) (*fin)++;
        if (flags[i] & 0x02) (*syn)++;
        if (flags[i] & 0x04) (*rst)++;
        if (flags[i] & 0x08) (*psh)++;
        if (flags[i] & 0x10) (*ack)++;
        if (flags[i] & 0x20) (*urg)++;
    }
}

/* ── Test helpers ─────────────────────────────────────────────────────────── */

static int tests_run    = 0;
static int tests_passed = 0;

#define TOLERANCE 1e-3f   // acceptable float difference

static void check_stats(const char *name, uint32_t count,
                        float avx_mean, float avx_std,
                        float ref_mean, float ref_std)
{
    tests_run++;
    float dm = fabsf(avx_mean - ref_mean);
    float ds = fabsf(avx_std  - ref_std);
    if (dm <= TOLERANCE && ds <= TOLERANCE) {
        printf("[PASS] %-40s  count=%-4u  mean=%.4f  std=%.4f\n",
               name, count, avx_mean, avx_std);
        tests_passed++;
    } else {
        printf("[FAIL] %-40s  count=%-4u\n"
               "       mean: avx=%.6f  ref=%.6f  diff=%.6f\n"
               "       std:  avx=%.6f  ref=%.6f  diff=%.6f\n",
               name, count, avx_mean, ref_mean, dm, avx_std, ref_std, ds);
    }
}

static void check_flags(const char *name, uint32_t count,
                        uint32_t af, uint32_t as_, uint32_t ar,
                        uint32_t ap, uint32_t aa, uint32_t au,
                        uint32_t rf, uint32_t rs, uint32_t rr,
                        uint32_t rp, uint32_t ra, uint32_t ru)
{
    tests_run++;
    if (af==rf && as_==rs && ar==rr && ap==rp && aa==ra && au==ru) {
        printf("[PASS] %-40s  count=%-4u  FIN=%u SYN=%u RST=%u PSH=%u ACK=%u URG=%u\n",
               name, count, af, as_, ar, ap, aa, au);
        tests_passed++;
    } else {
        printf("[FAIL] %-40s  count=%-4u\n"
               "       AVX: FIN=%u SYN=%u RST=%u PSH=%u ACK=%u URG=%u\n"
               "       REF: FIN=%u SYN=%u RST=%u PSH=%u ACK=%u URG=%u\n",
               name, count, af, as_, ar, ap, aa, au,
               rf, rs, rr, rp, ra, ru);
    }
}

/* ── Test cases ───────────────────────────────────────────────────────────── */

static void test_stats_uniform(void)
{
    uint16_t buf[64];
    for (int i = 0; i < 64; i++) buf[i] = 1000;
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 64, &am, &as_);
    scalar_pkt_len_stats(buf, 64, &rm, &rs);
    check_stats("stats_uniform_64 (all 1000)", 64, am, as_, rm, rs);
}

static void test_stats_single(void)
{
    uint16_t buf[1] = {500};
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 1, &am, &as_);
    scalar_pkt_len_stats(buf, 1, &rm, &rs);
    check_stats("stats_single_element", 1, am, as_, rm, rs);
}

static void test_stats_exact_16(void)
{
    // Exactly one AVX2 iteration
    uint16_t buf[16];
    for (int i = 0; i < 16; i++) buf[i] = (uint16_t)(i * 100 + 50);
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 16, &am, &as_);
    scalar_pkt_len_stats(buf, 16, &rm, &rs);
    check_stats("stats_exact_16 (ramp)", 16, am, as_, rm, rs);
}

static void test_stats_with_tail(void)
{
    // 16 + 7 = 23 — exercises scalar tail
    uint16_t buf[23];
    for (int i = 0; i < 23; i++) buf[i] = (uint16_t)(1 + (i * 37) % 1400);
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 23, &am, &as_);
    scalar_pkt_len_stats(buf, 23, &rm, &rs);
    check_stats("stats_23_with_7_tail", 23, am, as_, rm, rs);
}

static void test_stats_large(void)
{
    // 512 elements — max buffer size used in production
    uint16_t buf[512];
    for (int i = 0; i < 512; i++)
        buf[i] = (uint16_t)(40 + (i * 53 + 7) % 1460);
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 512, &am, &as_);
    scalar_pkt_len_stats(buf, 512, &rm, &rs);
    check_stats("stats_512_max_buffer", 512, am, as_, rm, rs);
}

static void test_stats_varied(void)
{
    // Mix of small (ACK-only ~40 bytes) and large (data ~1460 bytes) packets
    uint16_t buf[100];
    for (int i = 0; i < 100; i++)
        buf[i] = (i % 5 == 0) ? 40 : 1460;
    float am, as_, rm, rs;
    compute_pkt_len_stats_avx2(buf, 100, &am, &as_);
    scalar_pkt_len_stats(buf, 100, &rm, &rs);
    check_stats("stats_100_mixed_ack_data", 100, am, as_, rm, rs);
}

static void test_flags_all_syn(void)
{
    uint8_t flags[100];
    memset(flags, 0x02, 100);   // SYN bit only
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 100, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 100,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_100_all_SYN", 100,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

static void test_flags_all_ack(void)
{
    uint8_t flags[64];
    memset(flags, 0x10, 64);    // ACK bit only
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 64, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 64,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_64_all_ACK", 64,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

static void test_flags_syn_ack(void)
{
    uint8_t flags[32];
    memset(flags, 0x12, 32);    // SYN + ACK
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 32, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 32,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_32_SYN_ACK", 32,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

static void test_flags_rst_flood(void)
{
    // Simulates RST flood: 512 RST packets, key DoS signature
    uint8_t flags[512];
    memset(flags, 0x04, 512);
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 512, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 512,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_512_RST_flood", 512,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

static void test_flags_mixed(void)
{
    // Mixed: odd=ACK(0x10), even=PSH+ACK(0x18), every 7th=RST(0x04)
    uint8_t flags[200];
    for (int i = 0; i < 200; i++) {
        if (i % 7 == 0) flags[i] = 0x04;
        else if (i % 2 == 0) flags[i] = 0x18;
        else flags[i] = 0x10;
    }
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 200, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 200,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_200_mixed", 200,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

static void test_flags_tail_only(void)
{
    // 5 elements — entirely in scalar tail (< 32 per AVX2 loop)
    uint8_t flags[5] = {0x02, 0x12, 0x10, 0x04, 0x01};
    uint32_t af, as_, ar, ap, aa, au;
    uint32_t rf, rs, rr, rp, ra, ru;
    count_tcp_flags_avx2(flags, 5, &af, &as_, &ar, &ap, &aa, &au);
    scalar_count_flags(flags, 5,   &rf, &rs, &rr, &rp, &ra, &ru);
    check_flags("flags_5_scalar_tail_only", 5,
                af, as_, ar, ap, aa, au,
                rf, rs, rr, rp, ra, ru);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== AVX2 feature function unit tests ===\n\n");

    printf("-- compute_pkt_len_stats_avx2 --\n");
    test_stats_uniform();
    test_stats_single();
    test_stats_exact_16();
    test_stats_with_tail();
    test_stats_large();
    test_stats_varied();

    printf("\n-- count_tcp_flags_avx2 --\n");
    test_flags_all_syn();
    test_flags_all_ack();
    test_flags_syn_ack();
    test_flags_rst_flood();
    test_flags_mixed();
    test_flags_tail_only();

    printf("\n=== %d / %d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
