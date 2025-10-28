#include "json_output.h"
#include <string.h>
#include <time.h>

// 통계를 JSON 형식으로 출력
static void write_stats_json(FILE *fp, const char *name, stats_t *stats, bool last) {
    fprintf(fp, "        \"%s\": {\n", name);
    fprintf(fp, "          \"mean\": %.3f,\n", stats->mean);
    fprintf(fp, "          \"p50\": %.3f,\n", stats->p50);
    fprintf(fp, "          \"p90\": %.3f,\n", stats->p90);
    fprintf(fp, "          \"p99\": %.3f,\n", stats->p99);
    fprintf(fp, "          \"stddev\": %.3f\n", stats->stddev);
    fprintf(fp, "        }%s\n", last ? "" : ",");
}

// JSON 결과 파일 작성
void write_json_results(const char *filename, 
                        metadata_t *metadata,
                        benchmark_result_t *results,
                        int result_count,
                        const char **unavailable_algos,
                        int unavailable_count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return;
    }
    
    // 메타데이터
    fprintf(fp, "{\n");
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"library\": \"%s\",\n", metadata->library);
    fprintf(fp, "    \"version_or_commit\": \"%s\",\n", metadata->version_or_commit);
    fprintf(fp, "    \"platform\": \"%s\",\n", metadata->platform);
    fprintf(fp, "    \"network\": {\n");
    fprintf(fp, "      \"rtt_ms\": %d,\n", metadata->rtt_ms);
    fprintf(fp, "      \"mtu\": %d\n", metadata->mtu);
    fprintf(fp, "    },\n");
    fprintf(fp, "    \"cipher\": \"%s\",\n", metadata->cipher);
    fprintf(fp, "    \"tls_version\": \"%s\",\n", metadata->tls_version);
    fprintf(fp, "    \"mTLS\": %s,\n", metadata->mtls ? "true" : "false");
    fprintf(fp, "    \"runs_per_combo\": %d,\n", metadata->runs_per_combo);
    fprintf(fp, "    \"date\": \"%s\"\n", metadata->date);
    fprintf(fp, "  },\n");
    
    // 사용 불가능한 알고리즘
    if (unavailable_count > 0) {
        fprintf(fp, "  \"unavailable_algorithms\": [\n");
        for (int i = 0; i < unavailable_count; i++) {
            fprintf(fp, "    \"%s\"%s\n", unavailable_algos[i], 
                    i < unavailable_count - 1 ? "," : "");
        }
        fprintf(fp, "  ],\n");
    }
    
    // 결과 배열
    fprintf(fp, "  \"results\": [\n");
    
    for (int i = 0; i < result_count; i++) {
        benchmark_result_t *r = &results[i];
        
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"group\": \"%s\",\n", r->group);
        fprintf(fp, "      \"sigalg\": \"%s\",\n", r->sigalg);
        
        // 통계
        fprintf(fp, "      \"stats\": {\n");
        write_stats_json(fp, "t_handshake_total_ms", &r->t_handshake_total_ms, false);
        write_stats_json(fp, "t_clienthello_to_serverhello_ms", &r->t_clienthello_to_serverhello_ms, false);
        write_stats_json(fp, "t_cert_verify_ms", &r->t_cert_verify_ms, false);
        write_stats_json(fp, "t_finished_flight_ms", &r->t_finished_flight_ms, true);
        fprintf(fp, "      },\n");
        
        // 트래픽
        fprintf(fp, "      \"traffic\": {\n");
        fprintf(fp, "        \"bytes_tx_handshake\": %lu,\n", r->traffic_avg.bytes_tx_handshake);
        fprintf(fp, "        \"bytes_rx_handshake\": %lu,\n", r->traffic_avg.bytes_rx_handshake);
        fprintf(fp, "        \"records_count\": %u,\n", r->traffic_avg.records_count);
        fprintf(fp, "        \"packets_count\": %u,\n", r->traffic_avg.packets_count);
        fprintf(fp, "        \"retransmits\": %u\n", r->traffic_avg.retransmits);
        fprintf(fp, "      },\n");
        
        // 암호화
        fprintf(fp, "      \"crypto\": {\n");
        fprintf(fp, "        \"kem_keyshare_len\": %u,\n", r->crypto_avg.kem_keyshare_len);
        fprintf(fp, "        \"kem_encap_ms\": {\"client\": %.3f, \"server\": %.3f},\n",
                r->crypto_avg.kem_encap_ms_client, r->crypto_avg.kem_encap_ms_server);
        fprintf(fp, "        \"kem_decap_ms\": {\"client\": %.3f, \"server\": %.3f},\n",
                r->crypto_avg.kem_decap_ms_client, r->crypto_avg.kem_decap_ms_server);
        fprintf(fp, "        \"sig_len\": %u,\n", r->crypto_avg.sig_len);
        fprintf(fp, "        \"sign_ms\": {\"server\": %.3f, \"client\": %.3f},\n",
                r->crypto_avg.sign_ms_server, r->crypto_avg.sign_ms_client);
        fprintf(fp, "        \"verify_ms\": {\"server\": %.3f, \"client\": %.3f},\n",
                r->crypto_avg.verify_ms_server, r->crypto_avg.verify_ms_client);
        fprintf(fp, "        \"cert_chain_size_bytes\": {\"excluding_root\": %u, \"including_root\": %u}\n",
                r->crypto_avg.cert_chain_size_excluding_root, r->crypto_avg.cert_chain_size_including_root);
        fprintf(fp, "      },\n");
        
        // 리소스
        fprintf(fp, "      \"resources\": {\n");
        fprintf(fp, "        \"peak_heap_bytes\": %lu,\n", r->resources_avg.peak_heap_bytes);
        fprintf(fp, "        \"stack_usage_bytes\": %lu,\n", r->resources_avg.stack_usage_bytes);
        fprintf(fp, "        \"cpu_cycles\": %lu,\n", r->resources_avg.cpu_cycles);
        fprintf(fp, "        \"energy_mJ\": %.3f\n", r->resources_avg.energy_mJ);
        fprintf(fp, "      },\n");
        
        // 신뢰성
        fprintf(fp, "      \"reliability\": {\n");
        fprintf(fp, "        \"success_rate\": %.3f,\n", r->reliability_avg.success_rate);
        fprintf(fp, "        \"alert_codes\": [],\n");
        fprintf(fp, "        \"session_resumption_ok\": %s,\n", 
                r->reliability_avg.session_resumption_ok ? "true" : "false");
        fprintf(fp, "        \"t_resumption_ms\": %.3f,\n", r->reliability_avg.t_resumption_ms);
        fprintf(fp, "        \"zero_rtt_ok\": %s,\n", 
                r->reliability_avg.zero_rtt_ok ? "true" : "false");
        fprintf(fp, "        \"t_0rtt_ms\": %.3f\n", r->reliability_avg.t_0rtt_ms);
        fprintf(fp, "      }\n");
        
        fprintf(fp, "    }%s\n", i < result_count - 1 ? "," : "");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    printf("JSON results written to %s\n", filename);
}

// CSV 결과 파일 작성
void write_csv_results(const char *filename,
                       benchmark_result_t *results,
                       int result_count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return;
    }
    
    // 헤더
    fprintf(fp, "group,sigalg,t_total_ms_mean,t_total_ms_p50,t_total_ms_p90,");
    fprintf(fp, "bytes_tx,bytes_rx,kem_keyshare_len,sig_len,peak_heap_bytes,success_rate\n");
    
    // 데이터 행
    for (int i = 0; i < result_count; i++) {
        benchmark_result_t *r = &results[i];
        
        fprintf(fp, "%s,%s,%.3f,%.3f,%.3f,%lu,%lu,%u,%u,%lu,%.3f\n",
                r->group,
                r->sigalg,
                r->t_handshake_total_ms.mean,
                r->t_handshake_total_ms.p50,
                r->t_handshake_total_ms.p90,
                r->traffic_avg.bytes_tx_handshake,
                r->traffic_avg.bytes_rx_handshake,
                r->crypto_avg.kem_keyshare_len,
                r->crypto_avg.sig_len,
                r->resources_avg.peak_heap_bytes,
                r->reliability_avg.success_rate);
    }
    
    fclose(fp);
    printf("CSV results written to %s\n", filename);
}

