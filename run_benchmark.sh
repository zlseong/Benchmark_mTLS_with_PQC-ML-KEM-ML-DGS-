#!/bin/bash

# PQC Hybrid TLS 벤치마크 자동화 스크립트

set -e

# 설정
RUNS_PER_COMBO=30
SERVER_PORT=4433
CERTS_DIR="certs"
RESULTS_DIR="results"
PCAP_DIR="$RESULTS_DIR/pcap"
SERVER_BIN="build/tls_server"
CLIENT_BIN="build/tls_client"

# 색상
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "PQC Hybrid TLS 벤치마크"
echo "========================================"
echo "실행 횟수: $RUNS_PER_COMBO per combo"
echo "포트: $SERVER_PORT"
echo ""

# 디렉토리 생성
mkdir -p $RESULTS_DIR
mkdir -p $PCAP_DIR

# 빌드 확인
if [ ! -f "$SERVER_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    echo -e "${YELLOW}⚠️  빌드 파일이 없습니다. 먼저 'make'를 실행하세요.${NC}"
    exit 1
fi

# 인증서 확인
if [ ! -d "$CERTS_DIR" ] || [ ! -f "$CERTS_DIR/ca.crt" ]; then
    echo -e "${YELLOW}⚠️  인증서가 없습니다. 먼저 './generate_certs.sh'를 실행하세요.${NC}"
    exit 1
fi

# 알고리즘 조합
declare -a COMBOS=(
    "x25519:ecdsa_secp256r1_sha256"
    "mlkem512:ecdsa_secp256r1_sha256"
    "mlkem768:ecdsa_secp256r1_sha256"
    "mlkem1024:ecdsa_secp256r1_sha256"
    "mlkem512:dilithium2"
    "mlkem512:dilithium3"
    "mlkem512:dilithium5"
    "mlkem768:dilithium2"
    "mlkem768:dilithium3"
    "mlkem768:dilithium5"
    "mlkem1024:dilithium2"
    "mlkem1024:dilithium3"
    "mlkem1024:dilithium5"
)

total_combos=${#COMBOS[@]}
current=0

echo "총 조합: $total_combos"
echo ""

# 각 조합에 대해 벤치마크 실행
for combo in "${COMBOS[@]}"; do
    IFS=':' read -r group sigalg <<< "$combo"
    current=$((current + 1))
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[$current/$total_combos] $group + $sigalg${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    prefix="${group}_${sigalg}"
    server_cert="$CERTS_DIR/${prefix}_server.crt"
    server_key="$CERTS_DIR/${prefix}_server.key"
    client_cert="$CERTS_DIR/${prefix}_client.crt"
    client_key="$CERTS_DIR/${prefix}_client.key"
    ca_cert="$CERTS_DIR/ca.crt"
    
    # 인증서 파일 확인
    if [ ! -f "$server_cert" ] || [ ! -f "$client_cert" ]; then
        echo -e "${RED}  ❌ 인증서 파일을 찾을 수 없습니다. 건너뜁니다.${NC}"
        continue
    fi
    
    success_count=0
    
    # N회 반복 실행
    for run in $(seq 1 $RUNS_PER_COMBO); do
        printf "  [%2d/%d] " $run $RUNS_PER_COMBO
        
        # 서버 시작 (백그라운드)
        $SERVER_BIN "$server_cert" "$server_key" "$ca_cert" "$group" "$sigalg" $SERVER_PORT > /dev/null 2>&1 &
        SERVER_PID=$!
        
        # 서버 시작 대기
        sleep 0.5
        
        # 클라이언트 실행
        if $CLIENT_BIN "$client_cert" "$client_key" "$ca_cert" "$group" "$sigalg" "127.0.0.1" $SERVER_PORT > /dev/null 2>&1; then
            echo -e "${GREEN}✅${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}❌${NC}"
        fi
        
        # 서버 종료
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        
        # 포트 정리 대기
        sleep 0.2
    done
    
    echo -e "  ${GREEN}성공률: $success_count/$RUNS_PER_COMBO ($(awk "BEGIN {printf \"%.1f\", 100*$success_count/$RUNS_PER_COMBO}")%)${NC}"
    echo ""
done

echo ""
echo "========================================"
echo -e "${GREEN}✅ 벤치마크 완료!${NC}"
echo "========================================"
echo "결과 디렉토리: $RESULTS_DIR/"
echo ""
echo "다음 단계:"
echo "  1. 결과 분석"
echo "  2. JSON/CSV 생성 (구현 필요)"
echo "========================================"

