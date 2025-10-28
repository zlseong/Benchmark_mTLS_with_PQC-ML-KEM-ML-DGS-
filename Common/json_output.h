#ifndef JSON_OUTPUT_H
#define JSON_OUTPUT_H

#include "metrics.h"
#include <stdio.h>

// 메타데이터 구조체
typedef struct {
    char library[64];
    char version_or_commit[128];
    char platform[128];
    int rtt_ms;
    int mtu;
    char cipher[64];
    char tls_version[16];
    bool mtls;
    int runs_per_combo;
    char date[64];
} metadata_t;

// JSON 출력
void write_json_results(const char *filename, 
                        metadata_t *metadata,
                        benchmark_result_t *results,
                        int result_count,
                        const char **unavailable_algos,
                        int unavailable_count);

// CSV 출력
void write_csv_results(const char *filename,
                       benchmark_result_t *results,
                       int result_count);

#endif // JSON_OUTPUT_H

