#!/bin/bash

# PQC Hybrid TLS 인증서 생성 스크립트
# 13가지 알고리즘 조합에 대한 인증서 생성

set -e

OPENSSL="openssl"  # OpenSSL 3.x with PQC support
CERTS_DIR="certs"

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "========================================"
echo "PQC Hybrid TLS 인증서 생성"
echo "========================================"

# OpenSSL 버전 확인
echo ""
echo "OpenSSL 버전:"
$OPENSSL version

# 인증서 디렉토리 생성
mkdir -p $CERTS_DIR
cd $CERTS_DIR

# 알고리즘 조합 배열
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

# CA 인증서 생성 (ECDSA - 모든 조합에서 공통 사용)
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}CA 인증서 생성 (ECDSA)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ ! -f "ca.key" ]; then
    $OPENSSL ecparam -name prime256v1 -genkey -out ca.key
    $OPENSSL req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=PQC-Test/OU=CA/CN=PQC-Test-CA"
    echo -e "${GREEN}✅ CA 인증서 생성 완료${NC}"
else
    echo "CA 인증서가 이미 존재합니다."
fi

# 각 알고리즘 조합에 대해 인증서 생성
for combo in "${COMBOS[@]}"; do
    IFS=':' read -r group sigalg <<< "$combo"
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}생성 중: ${group} + ${sigalg}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    prefix="${group}_${sigalg}"
    
    # 서버 키 및 인증서 생성
    echo "  🔐 서버 키 생성..."
    
    if [[ "$sigalg" == "ecdsa_secp256r1_sha256" ]]; then
        # ECDSA 키 생성
        $OPENSSL ecparam -name prime256v1 -genkey -out ${prefix}_server.key
    elif [[ "$sigalg" == "dilithium"* ]]; then
        # Dilithium 키 생성
        $OPENSSL genpkey -algorithm $sigalg -out ${prefix}_server.key 2>/dev/null || {
            echo "  ⚠️  $sigalg 알고리즘을 사용할 수 없습니다. 건너뜁니다."
            continue
        }
    fi
    
    # 서버 CSR 생성
    $OPENSSL req -new -key ${prefix}_server.key -out ${prefix}_server.csr \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=PQC-Test/OU=Server/CN=localhost"
    
    # 서버 인증서 서명
    $OPENSSL x509 -req -in ${prefix}_server.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out ${prefix}_server.crt -days 365 -sha256
    
    echo "  📄 서버 인증서: ${prefix}_server.crt"
    
    # 클라이언트 키 및 인증서 생성
    echo "  🔐 클라이언트 키 생성..."
    
    if [[ "$sigalg" == "ecdsa_secp256r1_sha256" ]]; then
        $OPENSSL ecparam -name prime256v1 -genkey -out ${prefix}_client.key
    elif [[ "$sigalg" == "dilithium"* ]]; then
        $OPENSSL genpkey -algorithm $sigalg -out ${prefix}_client.key 2>/dev/null
    fi
    
    # 클라이언트 CSR 생성
    $OPENSSL req -new -key ${prefix}_client.key -out ${prefix}_client.csr \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=PQC-Test/OU=Client/CN=client"
    
    # 클라이언트 인증서 서명
    $OPENSSL x509 -req -in ${prefix}_client.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out ${prefix}_client.crt -days 365 -sha256
    
    echo "  📄 클라이언트 인증서: ${prefix}_client.crt"
    echo -e "${GREEN}  ✅ 완료${NC}"
    
    # CSR 파일 삭제
    rm -f ${prefix}_server.csr ${prefix}_client.csr
done

cd ..

echo ""
echo "========================================"
echo -e "${GREEN}✅ 모든 인증서 생성 완료!${NC}"
echo "========================================"
echo "인증서 위치: $CERTS_DIR/"
echo ""
echo "생성된 파일:"
echo "  - ca.crt, ca.key (CA)"
echo "  - <algo>_server.{crt,key} (서버용)"
echo "  - <algo>_client.{crt,key} (클라이언트용)"
echo "========================================"

