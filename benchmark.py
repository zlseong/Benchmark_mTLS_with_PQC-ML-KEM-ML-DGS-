#!/usr/bin/env python3
"""
PQC Hybrid TLS 벤치마크 자동화 스크립트
- 13가지 알고리즘 조합 자동 테스트
- 30회 반복 측정
- JSON/CSV 결과 출력
"""

import subprocess
import time
import json
import csv
import os
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
import statistics

# 설정
RUNS_PER_COMBO = 30
SERVER_PORT = 4433
CERTS_DIR = "certs"
RESULTS_DIR = "results"
PCAP_DIR = f"{RESULTS_DIR}/pcap"
SERVER_BIN = "build/tls_server"
CLIENT_BIN = "build/tls_client"

# 13가지 알고리즘 조합
ALGORITHM_COMBOS = [
    # Baseline
    ("x25519", "ecdsa_secp256r1_sha256"),
    
    # KEM + ECDSA
    ("mlkem512", "ecdsa_secp256r1_sha256"),
    ("mlkem768", "ecdsa_secp256r1_sha256"),
    ("mlkem1024", "ecdsa_secp256r1_sha256"),
    
    # KEM + ML-DSA (Dilithium)
    ("mlkem512", "dilithium2"),
    ("mlkem512", "dilithium3"),
    ("mlkem512", "dilithium5"),
    ("mlkem768", "dilithium2"),
    ("mlkem768", "dilithium3"),
    ("mlkem768", "dilithium5"),
    ("mlkem1024", "dilithium2"),
    ("mlkem1024", "dilithium3"),
    ("mlkem1024", "dilithium5"),
]

class Colors:
    """터미널 색상"""
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'  # No Color

class BenchmarkResult:
    """단일 실행 결과"""
    def __init__(self):
        self.success = False
        self.handshake_time_ms = 0.0
        self.error_msg = ""

class AggregatedResult:
    """집계된 결과 (N회 실행)"""
    def __init__(self, group: str, sigalg: str):
        self.group = group
        self.sigalg = sigalg
        self.times = []
        self.success_count = 0
        self.total_runs = 0
    
    def add_result(self, result: BenchmarkResult):
        """결과 추가"""
        self.total_runs += 1
        if result.success:
            self.success_count += 1
            self.times.append(result.handshake_time_ms)
    
    def get_stats(self) -> Dict:
        """통계 계산"""
        if not self.times:
            return {
                "mean": 0, "p50": 0, "p90": 0, "p99": 0, "stddev": 0
            }
        
        sorted_times = sorted(self.times)
        n = len(sorted_times)
        
        return {
            "mean": statistics.mean(sorted_times),
            "p50": sorted_times[int(n * 0.50)],
            "p90": sorted_times[int(n * 0.90)],
            "p99": sorted_times[int(n * 0.99)] if n > 1 else sorted_times[0],
            "stddev": statistics.stdev(sorted_times) if n > 1 else 0
        }
    
    def get_success_rate(self) -> float:
        """성공률"""
        return self.success_count / self.total_runs if self.total_runs > 0 else 0.0

def print_header():
    """헤더 출력"""
    print("=" * 60)
    print("PQC Hybrid TLS 벤치마크")
    print("=" * 60)
    print(f"실행 횟수: {RUNS_PER_COMBO} per combo")
    print(f"포트: {SERVER_PORT}")
    print(f"총 조합: {len(ALGORITHM_COMBOS)}")
    print(f"총 테스트: {len(ALGORITHM_COMBOS) * RUNS_PER_COMBO}")
    print()

def check_prerequisites() -> bool:
    """사전 조건 확인"""
    # 빌드 파일 확인
    if not os.path.exists(SERVER_BIN) or not os.path.exists(CLIENT_BIN):
        print(f"{Colors.RED}❌ 빌드 파일이 없습니다. 먼저 'make'를 실행하세요.{Colors.NC}")
        return False
    
    # 인증서 확인
    if not os.path.exists(CERTS_DIR) or not os.path.exists(f"{CERTS_DIR}/ca.crt"):
        print(f"{Colors.RED}❌ 인증서가 없습니다. 먼저 './generate_certs.sh'를 실행하세요.{Colors.NC}")
        return False
    
    # 결과 디렉토리 생성
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    Path(PCAP_DIR).mkdir(exist_ok=True)
    
    return True

def run_single_test(group: str, sigalg: str, run_num: int) -> BenchmarkResult:
    """단일 테스트 실행"""
    result = BenchmarkResult()
    
    prefix = f"{group}_{sigalg}"
    server_cert = f"{CERTS_DIR}/{prefix}_server.crt"
    server_key = f"{CERTS_DIR}/{prefix}_server.key"
    client_cert = f"{CERTS_DIR}/{prefix}_client.crt"
    client_key = f"{CERTS_DIR}/{prefix}_client.key"
    ca_cert = f"{CERTS_DIR}/ca.crt"
    
    # 인증서 파일 확인
    if not all(os.path.exists(f) for f in [server_cert, server_key, client_cert, client_key]):
        result.error_msg = "Certificate files not found"
        return result
    
    # 서버 시작
    server_cmd = [
        SERVER_BIN, server_cert, server_key, ca_cert,
        group, sigalg, str(SERVER_PORT)
    ]
    
    try:
        server_proc = subprocess.Popen(
            server_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # 서버 시작 대기
        time.sleep(0.5)
        
        # 클라이언트 실행
        client_cmd = [
            CLIENT_BIN, client_cert, client_key, ca_cert,
            group, sigalg, "127.0.0.1", str(SERVER_PORT)
        ]
        
        start_time = time.time()
        client_proc = subprocess.run(
            client_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        end_time = time.time()
        
        if client_proc.returncode == 0:
            result.success = True
            result.handshake_time_ms = (end_time - start_time) * 1000
        else:
            result.error_msg = f"Client failed with code {client_proc.returncode}"
        
    except subprocess.TimeoutExpired:
        result.error_msg = "Timeout"
    except Exception as e:
        result.error_msg = str(e)
    finally:
        # 서버 종료
        try:
            server_proc.terminate()
            server_proc.wait(timeout=2)
        except:
            server_proc.kill()
        
        # 포트 정리 대기
        time.sleep(0.2)
    
    return result

def run_benchmark_for_combo(group: str, sigalg: str, combo_num: int, total_combos: int) -> AggregatedResult:
    """알고리즘 조합에 대한 벤치마크 실행"""
    print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
    print(f"{Colors.BLUE}[{combo_num}/{total_combos}] {group} + {sigalg}{Colors.NC}")
    print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
    
    agg_result = AggregatedResult(group, sigalg)
    
    for run in range(1, RUNS_PER_COMBO + 1):
        result = run_single_test(group, sigalg, run)
        agg_result.add_result(result)
        
        # 진행 상황 출력
        status = f"{Colors.GREEN}✅{Colors.NC}" if result.success else f"{Colors.RED}❌{Colors.NC}"
        print(f"  [{run:2d}/{RUNS_PER_COMBO}] {status}", end="", flush=True)
        
        if result.success:
            print(f" {result.handshake_time_ms:.2f} ms")
        else:
            print(f" {result.error_msg}")
    
    # 통계 출력
    success_rate = agg_result.get_success_rate() * 100
    stats = agg_result.get_stats()
    
    print(f"\n  {Colors.GREEN}성공률: {agg_result.success_count}/{RUNS_PER_COMBO} ({success_rate:.1f}%){Colors.NC}")
    if agg_result.times:
        print(f"  평균: {stats['mean']:.2f} ms, p50: {stats['p50']:.2f} ms, p90: {stats['p90']:.2f} ms")
    print()
    
    return agg_result

def write_json_results(results: List[AggregatedResult], filename: str):
    """JSON 결과 저장"""
    metadata = {
        "library": "OpenSSL",
        "version_or_commit": "3.x",
        "platform": os.uname().sysname + " " + os.uname().machine,
        "network": {
            "rtt_ms": 0,
            "mtu": 1500
        },
        "cipher": "TLS_AES_128_GCM_SHA256",
        "tls_version": "1.3",
        "mTLS": True,
        "runs_per_combo": RUNS_PER_COMBO,
        "date": datetime.now().isoformat()
    }
    
    results_data = []
    for r in results:
        stats = r.get_stats()
        results_data.append({
            "group": r.group,
            "sigalg": r.sigalg,
            "stats": {
                "t_handshake_total_ms": stats
            },
            "reliability": {
                "success_rate": r.get_success_rate(),
                "total_runs": r.total_runs,
                "successful_runs": r.success_count
            }
        })
    
    output = {
        "metadata": metadata,
        "results": results_data
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"{Colors.GREEN}✅ JSON 저장: {filename}{Colors.NC}")

def write_csv_results(results: List[AggregatedResult], filename: str):
    """CSV 결과 저장"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'group', 'sigalg', 't_total_ms_mean', 't_total_ms_p50', 
            't_total_ms_p90', 't_total_ms_p99', 'success_rate'
        ])
        
        for r in results:
            stats = r.get_stats()
            writer.writerow([
                r.group,
                r.sigalg,
                f"{stats['mean']:.3f}",
                f"{stats['p50']:.3f}",
                f"{stats['p90']:.3f}",
                f"{stats['p99']:.3f}",
                f"{r.get_success_rate():.3f}"
            ])
    
    print(f"{Colors.GREEN}✅ CSV 저장: {filename}{Colors.NC}")

def main():
    """메인 함수"""
    print_header()
    
    if not check_prerequisites():
        return 1
    
    print(f"{Colors.GREEN}✅ 사전 조건 확인 완료{Colors.NC}\n")
    
    # 벤치마크 실행
    all_results = []
    
    for i, (group, sigalg) in enumerate(ALGORITHM_COMBOS, 1):
        result = run_benchmark_for_combo(group, sigalg, i, len(ALGORITHM_COMBOS))
        all_results.append(result)
    
    # 결과 저장
    print()
    print("=" * 60)
    print("결과 저장 중...")
    print("=" * 60)
    
    json_file = f"{RESULTS_DIR}/tls13_pqc_benchmark.json"
    csv_file = f"{RESULTS_DIR}/tls13_pqc_benchmark.csv"
    
    write_json_results(all_results, json_file)
    write_csv_results(all_results, csv_file)
    
    print()
    print("=" * 60)
    print(f"{Colors.GREEN}✅ 벤치마크 완료!{Colors.NC}")
    print("=" * 60)
    print(f"결과 디렉토리: {RESULTS_DIR}/")
    print(f"  - {json_file}")
    print(f"  - {csv_file}")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    exit(main())

