# Benchmark of PQC_hybrid-TLS

양자 내성(PQC) 알고리즘과 기존 암호를 혼합한 하이브리드 mTLS 실험용 레포지토리입니다. 서버/클라이언트 간 TLS 핸드셰이크 성능과 성공률을 측정하고, JSON/콘솔 형태로 결과를 출력합니다.

## 주요 기능
- 하이브리드 mTLS 핸드셰이크 구현(서버/클라이언트)
- 알고리즘/파라미터 선택(`Common/algo_config.h`)
- 성능·지표 수집(`Common/metrics.*`) 및 JSON 출력(`Common/json_output.*`)
- 자동 인증서 생성 스크립트(`generate_certs.sh`)
- 벤치마크 스크립트(`run_benchmark.sh`, `benchmark.py`)

## 디렉토리 구조
- `Server/tls_server.c`: mTLS 서버 구현
- `Client/tls_client.c`: mTLS 클라이언트 구현
- `Common/`: 공용 설정, 메트릭, JSON 출력 유틸
- `generate_certs.sh`: 실험용 인증서 생성
- `run_benchmark.sh`: 반복 실행 및 결과 수집
- `benchmark.py`: 결과 처리/시각화(옵션)
- `Makefile`: 빌드 스크립트
- `README.md`: 이 문서

## 요구 사항
- Linux 또는 WSL2 환경 권장(Windows의 경우 WSL2 사용)
- GCC/Clang 및 Make
- OpenSSL(또는 빌드/런타임에 필요한 TLS 라이브러리)
- Python 3.x (벤치마크/분석 시)

## 빠른 시작
```bash
# 1) 의존성 설치(예: Ubuntu/WSL)
sudo apt update
sudo apt install -y build-essential clang make openssl libssl-dev python3 python3-pip

# 2) 인증서 생성
chmod +x generate_certs.sh
./generate_certs.sh

# 3) 빌드
make clean && make

# 4) 서버 실행(터미널 A)
./server

# 5) 클라이언트 실행(터미널 B)
./client
```

## 벤치마크 실행
```bash
# 쉘 스크립트 기반 반복 측정
chmod +x run_benchmark.sh
./run_benchmark.sh

# 또는 Python 스크립트 사용(필요 시 의존성 설치)
# pip install -r requirements.txt  # 존재할 경우
python3 benchmark.py
```

## 알고리즘 구성 변경
- `Common/algo_config.h`에서 하이브리드 구성(PQC + 기존 암호)을 선택/수정합니다.
- 변경 후 `make`로 재빌드합니다.

## 결과/로그
- 표준 출력: 진행 로그 및 요약 메트릭
- JSON: `Common/json_output.*`를 통해 파일로 저장 가능(스크립트에서 경로 지정)

## 트러블슈팅
- 인증서/키 오류: `generate_certs.sh`를 재실행하고 산출 파일 권한 확인
- 라이브러리 링크 오류: `libssl-dev` 설치 및 `Makefile`의 링크 플래그 확인
- WSL 네트워킹 이슈: 서버/클라이언트 동일 환경(동일 WSL)에서 먼저 테스트

## 라이선스
본 레포지토리의 라이선스는 `LICENSE` 파일을 참고하세요.
