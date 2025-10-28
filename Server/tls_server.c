#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "../Common/metrics.h"

#define DEFAULT_PORT 4433
#define BUFFER_SIZE 4096

typedef struct {
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *groups;
    const char *sigalgs;
    int port;
} server_config_t;

// OpenSSL 오류 출력
static void print_ssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

// SSL 컨텍스트 생성
static SSL_CTX* create_context(server_config_t *config) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
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

    // 서버 인증서 로드
    if (SSL_CTX_use_certificate_file(ctx, config->cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 서버 개인키 로드
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load private key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // mTLS 설정: 클라이언트 인증서 요구
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    // CA 인증서 로드
    if (SSL_CTX_load_verify_locations(ctx, config->ca_file, NULL) != 1) {
        print_ssl_error("Failed to load CA certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// 소켓 생성 및 바인딩
static int create_socket(int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        return -1;
    }

    // SO_REUSEADDR 설정
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        close(sock);
        return -1;
    }

    return sock;
}

// 클라이언트 처리
static void handle_client(SSL *ssl, handshake_metrics_t *metrics) {
    timer_t handshake_timer;
    
    init_handshake_metrics(metrics);
    start_timer(&handshake_timer);
    
    // SSL 핸드셰이크
    if (SSL_accept(ssl) <= 0) {
        print_ssl_error("SSL_accept failed");
        metrics->success = false;
        snprintf(metrics->error_msg, sizeof(metrics->error_msg), "SSL_accept failed");
        return;
    }
    
    metrics->t_handshake_total_ms = end_timer(&handshake_timer);
    metrics->success = true;
    
    // 핸드셰이크 완료 후 클라이언트로부터 메시지 수신
    char buf[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        buf[bytes] = '\0';
        printf("Received from client: %s\n", buf);
        
        // 응답 전송
        const char *reply = "OK";
        SSL_write(ssl, reply, strlen(reply));
    }
    
    // 메트릭 수집
    // TODO: BIO를 사용해 실제 트래픽 측정
    metrics->traffic.bytes_tx_handshake = 0;  // 임시
    metrics->traffic.bytes_rx_handshake = 0;  // 임시
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <cert> <key> <ca> <groups> [sigalgs] [port]\n", argv[0]);
        fprintf(stderr, "Example: %s server.crt server.key ca.crt x25519 ecdsa_secp256r1_sha256 4433\n", argv[0]);
        return 1;
    }

    server_config_t config = {
        .cert_file = argv[1],
        .key_file = argv[2],
        .ca_file = argv[3],
        .groups = argv[4],
        .sigalgs = argc > 5 ? argv[5] : NULL,
        .port = argc > 6 ? atoi(argv[6]) : DEFAULT_PORT
    };

    printf("Starting TLS 1.3 Server (mTLS enabled)...\n");
    printf("Port: %d\n", config.port);
    printf("Groups: %s\n", config.groups);
    printf("Sigalgs: %s\n", config.sigalgs ? config.sigalgs : "(default)");
    printf("Cipher: TLS_AES_128_GCM_SHA256\n");

    // OpenSSL 초기화
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // SSL 컨텍스트 생성
    SSL_CTX *ctx = create_context(&config);
    if (!ctx) {
        return 1;
    }

    // 소켓 생성
    int sock = create_socket(config.port);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Server listening on port %d...\n", config.port);

    // 클라이언트 연결 대기
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            continue;
        }

        printf("Connection from %s:%d\n", 
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        handshake_metrics_t metrics;
        handle_client(ssl, &metrics);

        if (metrics.success) {
            printf("✅ Handshake successful (%.2f ms)\n", metrics.t_handshake_total_ms);
        } else {
            printf("❌ Handshake failed: %s\n", metrics.error_msg);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

