#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "../Common/metrics.h"

#define DEFAULT_PORT 4433
#define DEFAULT_HOST "127.0.0.1"
#define BUFFER_SIZE 4096

typedef struct {
    const char *host;
    int port;
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *groups;
    const char *sigalgs;
} client_config_t;

// OpenSSL 오류 출력
static void print_ssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

// SSL 컨텍스트 생성
static SSL_CTX* create_context(client_config_t *config) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        print_ssl_error("Unable to create SSL context");
        return NULL;
    }

    // TLS 1.3만 사용
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Cipher suite 고정: TLS_AES_128_GCM_SHA256
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1) {
        print_ssl_error("Failed to set cipher suite");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 그룹 설정 (KEM)
    if (config->groups && SSL_CTX_set1_groups_list(ctx, config->groups) != 1) {
        fprintf(stderr, "Warning: Failed to set groups: %s\n", config->groups);
    }

    // 서명 알고리즘 설정
    if (config->sigalgs && SSL_CTX_set1_sigalgs_list(ctx, config->sigalgs) != 1) {
        fprintf(stderr, "Warning: Failed to set sigalgs: %s\n", config->sigalgs);
    }

    // 클라이언트 인증서 로드 (mTLS)
    if (SSL_CTX_use_certificate_file(ctx, config->cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 클라이언트 개인키 로드
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client private key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // CA 인증서 로드 (서버 검증용)
    if (SSL_CTX_load_verify_locations(ctx, config->ca_file, NULL) != 1) {
        print_ssl_error("Failed to load CA certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 서버 인증서 검증 활성화
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

// 서버에 연결
static int connect_to_server(const char *host, int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    return sock;
}

// TLS 핸드셰이크 수행 및 메트릭 수집
static bool perform_handshake(SSL *ssl, handshake_metrics_t *metrics) {
    timer_t total_timer, ch_to_sh_timer;
    
    init_handshake_metrics(metrics);
    
    // 전체 핸드셰이크 타이머 시작
    start_timer(&total_timer);
    start_timer(&ch_to_sh_timer);
    
    // SSL 핸드셰이크
    int ret = SSL_connect(ssl);
    
    metrics->t_clienthello_to_serverhello_ms = end_timer(&ch_to_sh_timer);
    
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        print_ssl_error("SSL_connect failed");
        metrics->success = false;
        snprintf(metrics->error_msg, sizeof(metrics->error_msg), 
                "SSL_connect failed with error %d", err);
        return false;
    }
    
    metrics->t_handshake_total_ms = end_timer(&total_timer);
    metrics->success = true;
    
    // 협상된 프로토콜 정보 출력
    const char *version = SSL_get_version(ssl);
    const char *cipher = SSL_get_cipher(ssl);
    
    printf("  Protocol: %s\n", version);
    printf("  Cipher: %s\n", cipher);
    
    // 서버 인증서 정보
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        printf("  Server cert: %s\n", subject);
        OPENSSL_free(subject);
        X509_free(cert);
    }
    
    return true;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <cert> <key> <ca> <groups> [sigalgs] [host] [port]\n", argv[0]);
        fprintf(stderr, "Example: %s client.crt client.key ca.crt x25519 ecdsa_secp256r1_sha256 127.0.0.1 4433\n", argv[0]);
        return 1;
    }

    client_config_t config = {
        .cert_file = argv[1],
        .key_file = argv[2],
        .ca_file = argv[3],
        .groups = argv[4],
        .sigalgs = argc > 5 ? argv[5] : NULL,
        .host = argc > 6 ? argv[6] : DEFAULT_HOST,
        .port = argc > 7 ? atoi(argv[7]) : DEFAULT_PORT
    };

    printf("TLS 1.3 Client (mTLS enabled)\n");
    printf("Connecting to %s:%d\n", config.host, config.port);
    printf("Groups: %s\n", config.groups);
    printf("Sigalgs: %s\n", config.sigalgs ? config.sigalgs : "(default)");
    printf("Cipher: TLS_AES_128_GCM_SHA256\n\n");

    // OpenSSL 초기화
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // SSL 컨텍스트 생성
    SSL_CTX *ctx = create_context(&config);
    if (!ctx) {
        return 1;
    }

    // 서버에 연결
    int sock = connect_to_server(config.host, config.port);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    // SSL 객체 생성
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 핸드셰이크 수행
    handshake_metrics_t metrics;
    if (perform_handshake(ssl, &metrics)) {
        printf("\n✅ Handshake successful!\n");
        printf("  Total time: %.2f ms\n", metrics.t_handshake_total_ms);
        printf("  ClientHello->ServerHello: %.2f ms\n", metrics.t_clienthello_to_serverhello_ms);

        // 메시지 전송
        const char *msg = "Hello from client";
        SSL_write(ssl, msg, strlen(msg));
        
        // 응답 수신
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("  Server response: %s\n", buf);
        }
    } else {
        printf("\n❌ Handshake failed: %s\n", metrics.error_msg);
    }

    // 정리
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return metrics.success ? 0 : 1;
}

