#include "metrics.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

// 타이머 시작
void start_timer(timer_t *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->start);
}

// 타이머 종료 및 밀리초 반환
double end_timer(timer_t *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->end);
    
    double start_ms = timer->start.tv_sec * 1000.0 + timer->start.tv_nsec / 1000000.0;
    double end_ms = timer->end.tv_sec * 1000.0 + timer->end.tv_nsec / 1000000.0;
    
    return end_ms - start_ms;
}

// 비교 함수 (qsort용)
static int compare_double(const void *a, const void *b) {
    double diff = *(double*)a - *(double*)b;
    return (diff > 0) - (diff < 0);
}

// 통계 계산
void calculate_stats(double *values, int count, stats_t *stats) {
    if (count == 0) {
        memset(stats, 0, sizeof(stats_t));
        return;
    }
    
    // 정렬
    double *sorted = malloc(count * sizeof(double));
    memcpy(sorted, values, count * sizeof(double));
    qsort(sorted, count, sizeof(double), compare_double);
    
    // 평균
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += sorted[i];
    }
    stats->mean = sum / count;
    
    // 백분위수
    stats->p50 = sorted[(int)(count * 0.50)];
    stats->p90 = sorted[(int)(count * 0.90)];
    stats->p99 = sorted[(int)(count * 0.99)];
    
    // 표준편차
    double variance = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = sorted[i] - stats->mean;
        variance += diff * diff;
    }
    stats->stddev = sqrt(variance / count);
    
    free(sorted);
}

// 메트릭 초기화
void init_handshake_metrics(handshake_metrics_t *metrics) {
    memset(metrics, 0, sizeof(handshake_metrics_t));
    metrics->success = false;
}

void init_benchmark_result(benchmark_result_t *result) {
    memset(result, 0, sizeof(benchmark_result_t));
}

// 메트릭 집계
void aggregate_metrics(handshake_metrics_t *metrics, int count, benchmark_result_t *result) {
    result->total_runs = count;
    result->successful_runs = 0;
    
    // 시간 메트릭용 배열
    double *t_total = malloc(count * sizeof(double));
    double *t_ch_to_sh = malloc(count * sizeof(double));
    double *t_cert_verify = malloc(count * sizeof(double));
    double *t_finished = malloc(count * sizeof(double));
    
    int valid_count = 0;
    
    // 트래픽, 암호화, 리소스 메트릭 평균 계산
    uint64_t total_bytes_tx = 0, total_bytes_rx = 0;
    uint32_t total_records = 0, total_packets = 0, total_retransmits = 0;
    uint64_t total_heap = 0, total_stack = 0, total_cycles = 0;
    double total_energy = 0.0;
    
    for (int i = 0; i < count; i++) {
        if (metrics[i].success) {
            result->successful_runs++;
            
            t_total[valid_count] = metrics[i].t_handshake_total_ms;
            t_ch_to_sh[valid_count] = metrics[i].t_clienthello_to_serverhello_ms;
            t_cert_verify[valid_count] = metrics[i].t_cert_verify_ms;
            t_finished[valid_count] = metrics[i].t_finished_flight_ms;
            valid_count++;
            
            total_bytes_tx += metrics[i].traffic.bytes_tx_handshake;
            total_bytes_rx += metrics[i].traffic.bytes_rx_handshake;
            total_records += metrics[i].traffic.records_count;
            total_packets += metrics[i].traffic.packets_count;
            total_retransmits += metrics[i].traffic.retransmits;
            
            total_heap += metrics[i].resources.peak_heap_bytes;
            total_stack += metrics[i].resources.stack_usage_bytes;
            total_cycles += metrics[i].resources.cpu_cycles;
            total_energy += metrics[i].resources.energy_mJ;
        }
    }
    
    // 통계 계산
    if (valid_count > 0) {
        calculate_stats(t_total, valid_count, &result->t_handshake_total_ms);
        calculate_stats(t_ch_to_sh, valid_count, &result->t_clienthello_to_serverhello_ms);
        calculate_stats(t_cert_verify, valid_count, &result->t_cert_verify_ms);
        calculate_stats(t_finished, valid_count, &result->t_finished_flight_ms);
        
        // 평균값
        result->traffic_avg.bytes_tx_handshake = total_bytes_tx / valid_count;
        result->traffic_avg.bytes_rx_handshake = total_bytes_rx / valid_count;
        result->traffic_avg.records_count = total_records / valid_count;
        result->traffic_avg.packets_count = total_packets / valid_count;
        result->traffic_avg.retransmits = total_retransmits / valid_count;
        
        result->resources_avg.peak_heap_bytes = total_heap / valid_count;
        result->resources_avg.stack_usage_bytes = total_stack / valid_count;
        result->resources_avg.cpu_cycles = total_cycles / valid_count;
        result->resources_avg.energy_mJ = total_energy / valid_count;
        
        // 성공률
        result->reliability_avg.success_rate = (double)result->successful_runs / result->total_runs;
    }
    
    // 첫 번째 성공한 실행의 암호화 메트릭 사용
    for (int i = 0; i < count; i++) {
        if (metrics[i].success) {
            result->crypto_avg = metrics[i].crypto;
            break;
        }
    }
    
    free(t_total);
    free(t_ch_to_sh);
    free(t_cert_verify);
    free(t_finished);
}

