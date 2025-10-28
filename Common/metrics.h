#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// 시간 측정을 위한 구조체
typedef struct {
    struct timespec start;
    struct timespec end;
} timer_t;

// 통계 구조체
typedef struct {
    double mean;
    double p50;
    double p90;
    double p99;
    double stddev;
} stats_t;

// 암호화 메트릭
typedef struct {
    uint32_t kem_keyshare_len;
    double kem_encap_ms_client;
    double kem_encap_ms_server;
    double kem_decap_ms_client;
    double kem_decap_ms_server;
    uint32_t sig_len;
    double sign_ms_server;
    double sign_ms_client;
    double verify_ms_server;
    double verify_ms_client;
    uint32_t cert_chain_size_excluding_root;
    uint32_t cert_chain_size_including_root;
} crypto_metrics_t;

// 트래픽 메트릭
typedef struct {
    uint64_t bytes_tx_handshake;
    uint64_t bytes_rx_handshake;
    uint32_t records_count;
    uint32_t packets_count;
    uint32_t retransmits;
} traffic_metrics_t;

// 리소스 메트릭
typedef struct {
    uint64_t peak_heap_bytes;
    uint64_t stack_usage_bytes;
    uint64_t cpu_cycles;
    double energy_mJ;
} resource_metrics_t;

// 신뢰성 메트릭
typedef struct {
    double success_rate;
    int alert_codes[16];
    int alert_count;
    bool session_resumption_ok;
    double t_resumption_ms;
    bool zero_rtt_ok;
    double t_0rtt_ms;
} reliability_metrics_t;

// 핸드셰이크 메트릭 (단일 실행)
typedef struct {
    double t_handshake_total_ms;
    double t_clienthello_to_serverhello_ms;
    double t_cert_verify_ms;
    double t_finished_flight_ms;
    double rtt_ms;
    
    traffic_metrics_t traffic;
    crypto_metrics_t crypto;
    resource_metrics_t resources;
    reliability_metrics_t reliability;
    
    bool success;
    char error_msg[256];
} handshake_metrics_t;

// 벤치마크 결과 (N회 실행 집계)
typedef struct {
    char group[64];
    char sigalg[64];
    
    stats_t t_handshake_total_ms;
    stats_t t_clienthello_to_serverhello_ms;
    stats_t t_cert_verify_ms;
    stats_t t_finished_flight_ms;
    
    traffic_metrics_t traffic_avg;
    crypto_metrics_t crypto_avg;
    resource_metrics_t resources_avg;
    reliability_metrics_t reliability_avg;
    
    int total_runs;
    int successful_runs;
} benchmark_result_t;

// 타이머 함수
void start_timer(timer_t *timer);
double end_timer(timer_t *timer);

// 통계 계산
void calculate_stats(double *values, int count, stats_t *stats);

// 메트릭 초기화
void init_handshake_metrics(handshake_metrics_t *metrics);
void init_benchmark_result(benchmark_result_t *result);

// 메트릭 집계
void aggregate_metrics(handshake_metrics_t *metrics, int count, benchmark_result_t *result);

#endif // METRICS_H

