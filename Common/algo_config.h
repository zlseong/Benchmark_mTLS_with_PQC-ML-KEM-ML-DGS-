#ifndef ALGO_CONFIG_H
#define ALGO_CONFIG_H

// 알고리즘 조합 정의
typedef struct {
    const char *group;
    const char *sigalg;
    int ossl_group_nid;  // OpenSSL NID (runtime에서 조회)
    int ossl_sigalg_nid; // OpenSSL NID (runtime에서 조회)
} algo_combo_t;

// 13가지 알고리즘 조합
static const algo_combo_t ALGO_COMBOS[] = {
    // Baseline (1)
    {"x25519", "ecdsa_secp256r1_sha256", 0, 0},
    
    // KEM + ECDSA (3)
    {"mlkem512", "ecdsa_secp256r1_sha256", 0, 0},
    {"mlkem768", "ecdsa_secp256r1_sha256", 0, 0},
    {"mlkem1024", "ecdsa_secp256r1_sha256", 0, 0},
    
    // KEM + ML-DSA (9)
    {"mlkem512", "mldsa44", 0, 0},
    {"mlkem512", "mldsa65", 0, 0},
    {"mlkem512", "mldsa87", 0, 0},
    
    {"mlkem768", "mldsa44", 0, 0},
    {"mlkem768", "mldsa65", 0, 0},
    {"mlkem768", "mldsa87", 0, 0},
    
    {"mlkem1024", "mldsa44", 0, 0},
    {"mlkem1024", "mldsa65", 0, 0},
    {"mlkem1024", "mldsa87", 0, 0},
};

#define ALGO_COMBO_COUNT (sizeof(ALGO_COMBOS) / sizeof(algo_combo_t))

// OpenSSL 3.x에서 사용되는 그룹명 매핑
static const char* get_openssl_group_name(const char *group) {
    if (strcmp(group, "x25519") == 0) return "x25519";
    if (strcmp(group, "mlkem512") == 0) return "mlkem512";
    if (strcmp(group, "mlkem768") == 0) return "mlkem768";
    if (strcmp(group, "mlkem1024") == 0) return "mlkem1024";
    return group;
}

// OpenSSL 3.x에서 사용되는 서명 알고리즘명 매핑
static const char* get_openssl_sigalg_name(const char *sigalg) {
    if (strcmp(sigalg, "ecdsa_secp256r1_sha256") == 0) return "ecdsa_secp256r1_sha256";
    if (strcmp(sigalg, "mldsa44") == 0) return "dilithium2";
    if (strcmp(sigalg, "mldsa65") == 0) return "dilithium3";
    if (strcmp(sigalg, "mldsa87") == 0) return "dilithium5";
    return sigalg;
}

#endif // ALGO_CONFIG_H

