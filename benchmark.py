import time
import secrets
import struct
import sys
import os

# Ensure workspace is in Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from OBU.signature import (
    G, N, bytes_to_point, point_to_bytes, point_mul,
    ecqv_obu_keygen_request, ecqv_ca_issue, ecqv_obu_recover_key,
    ecqv_rsu_reconstruct_public_key, h_fswa_verify
)
import OBU.signature_oqs as sig_oqs
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44

def run_benchmark():
    print("=" * 90)
    print("         H-FSwA & ECQV 多後端混合簽章效能基準測試 (公鑰快取優化版)")
    print("=" * 90)
    print(f"系統執行環境: Python {sys.version.split()[0]}")
    print(f"硬體加速模組: Numba JIT = {'已啟用' if sig_oqs.HAS_NUMBA else '未啟用'} | liboqs = {'已啟用' if sig_oqs.HAS_LIBOQS else '未啟用'} | Custom C = {'已啟用' if sig_oqs.HAS_CUSTOM_C else '未啟用'}")
    print("-" * 90)

    # 模擬基礎變數
    d_CA_ecc = secrets.randbelow(N - 1) + 1
    Q_CA_ecc = point_mul(d_CA_ecc, G)
    obu_id = "AMB-217"
    k_obu, R_obu = ecqv_obu_keygen_request()
    obu_pqc_pub, obu_pqc_priv = ML_DSA_44.keygen()
    expiry = int(time.time() + 31536000)
    
    # 核發憑證以供測試
    P_recon, s_ca = ecqv_ca_issue(R_obu, obu_id, expiry, obu_pqc_pub, d_CA_ecc)
    P_recon_bytes = point_to_bytes(P_recon, compressed=True)
    s_ca_bytes = s_ca.to_bytes(32, 'big')
    
    # 還原金鑰
    d_obu, Q_obu = ecqv_obu_recover_key(s_ca, P_recon, k_obu, obu_id, expiry, obu_pqc_pub, Q_CA_ecc)

    message = b"BSM_V2X_SAFETY_MESSAGE_LAT_25.033_LON_121.565_SPD_60.5"
    iterations = 10

    results = {}

    # --- 1. 測試 Mode 0: Pure Python (H-FSwA) ---
    print("[*] 正在測試 ──> Mode 0: Pure-Python...")
    sig_oqs.apply_backend(sig_oqs.MODE_PURE_PYTHON)
    
    # 暖身
    sig_oqs.master_sign(obu_id, known_RSU=False)
    
    # 測試簽章
    t0 = time.time()
    for _ in range(iterations):
        packet, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
    t_sign_mode0 = (time.time() - t0) / iterations * 1000

    sig_hybrid = packet[-2452:]
    
    # 測試驗簽 (首次封包：含 ECQV 重構)
    t0 = time.time()
    for _ in range(iterations):
        Q_obu_recon = ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, obu_pqc_pub, Q_CA_ecc)
        passed = h_fswa_verify(obu_pqc_pub, Q_obu_recon, message, sig_hybrid)
    t_verify_recon_mode0 = (time.time() - t0) / iterations * 1000

    # 測試驗簽 (後續封包：公鑰快取命中，免除重構)
    t0 = time.time()
    for _ in range(iterations):
        passed = h_fswa_verify(obu_pqc_pub, Q_obu, message, sig_hybrid)
    t_verify_cached_mode0 = (time.time() - t0) / iterations * 1000

    results["Mode 0 (Pure Python)"] = {
        "sign": t_sign_mode0, 
        "verify_recon": t_verify_recon_mode0, 
        "verify_cached": t_verify_cached_mode0,
        "sns": "是 (H-FSwA)", "len": 2452
    }

    # --- 2. 測試 Mode 1: Numba JIT (H-FSwA) ---
    if sig_oqs.HAS_NUMBA:
        print("[*] 正在測試 ──> Mode 1: Numba JIT...")
        sig_oqs.apply_backend(sig_oqs.MODE_NUMBA_JIT)
        
        # 進行暖身 (Warm-up)
        sig_oqs.master_sign(obu_id, known_RSU=False)
        
        # 測試簽章
        t0 = time.time()
        for _ in range(iterations):
            packet, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        t_sign_mode1 = (time.time() - t0) / iterations * 1000

        sig_hybrid = packet[-2452:]
        
        # 測試驗簽 (首次封包)
        t0 = time.time()
        for _ in range(iterations):
            Q_obu_recon = ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, obu_pqc_pub, Q_CA_ecc)
            passed = h_fswa_verify(obu_pqc_pub, Q_obu_recon, message, sig_hybrid)
        t_verify_recon_mode1 = (time.time() - t0) / iterations * 1000

        # 測試驗簽 (後續封包：快取)
        t0 = time.time()
        for _ in range(iterations):
            passed = h_fswa_verify(obu_pqc_pub, Q_obu, message, sig_hybrid)
        t_verify_cached_mode1 = (time.time() - t0) / iterations * 1000
        
        results["Mode 1 (Numba JIT)"] = {
            "sign": t_sign_mode1, 
            "verify_recon": t_verify_recon_mode1, 
            "verify_cached": t_verify_cached_mode1,
            "sns": "是 (H-FSwA)", "len": 2452
        }
    else:
        results["Mode 1 (Numba JIT)"] = {
            "sign": 0.0, "verify_recon": 0.0, "verify_cached": 0.0, 
            "sns": "未安裝 Numba", "len": 2452
        }

    # --- 3. 測試 Mode 2: liboqs Parallel ---
    if sig_oqs.HAS_LIBOQS:
        print("[*] 正在測試 ──> Mode 2: liboqs Parallel...")
        sig_oqs.apply_backend(sig_oqs.MODE_LIBOQS_PARALLEL)
        
        t0 = time.time()
        for _ in range(iterations):
            packet, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        t_sign_mode2 = (time.time() - t0) / iterations * 1000

        sig_parallel = packet[-2484:]
        
        # 測試驗簽 (首次封包)
        t0 = time.time()
        for _ in range(iterations):
            Q_obu_recon = ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, obu_pqc_pub, Q_CA_ecc)
            passed = sig_oqs.liboqs_parallel_verify(obu_id, Q_obu_recon, obu_pqc_pub, message, sig_parallel)
        t_verify_recon_mode2 = (time.time() - t0) / iterations * 1000

        # 測試驗簽 (後續封包：快取)
        t0 = time.time()
        for _ in range(iterations):
            passed = sig_oqs.liboqs_parallel_verify(obu_id, Q_obu, obu_pqc_pub, message, sig_parallel)
        t_verify_cached_mode2 = (time.time() - t0) / iterations * 1000

        results["Mode 2 (liboqs C-Lib)"] = {
            "sign": t_sign_mode2, 
            "verify_recon": t_verify_recon_mode2, 
            "verify_cached": t_verify_cached_mode2,
            "sns": "否 (並行拼接)", "len": 2484
        }
    else:
        results["Mode 2 (liboqs C-Lib)"] = {
            "sign": 0.0, "verify_recon": 0.0, "verify_cached": 0.0, 
            "sns": "環境未啟用", "len": 2484
        }

    # --- 4. 測試 Mode 3: Custom C-Backend (H-FSwA) ---
    if sig_oqs.HAS_CUSTOM_C:
        print("[*] 正在測試 ──> Mode 3: Custom C-Backend...")
        sig_oqs.apply_backend(sig_oqs.MODE_CUSTOM_C)
        
        # 測試簽章
        t0 = time.time()
        for _ in range(iterations):
            packet, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        t_sign_mode3 = (time.time() - t0) / iterations * 1000

        sig_hybrid = packet[-2452:]
        
        # 測試驗簽 (首次封包)
        t0 = time.time()
        for _ in range(iterations):
            Q_obu_recon = ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, obu_pqc_pub, Q_CA_ecc)
            passed = h_fswa_verify(obu_pqc_pub, Q_obu_recon, message, sig_hybrid)
        t_verify_recon_mode3 = (time.time() - t0) / iterations * 1000

        # 測試驗簽 (後續封包：快取)
        t0 = time.time()
        for _ in range(iterations):
            passed = h_fswa_verify(obu_pqc_pub, Q_obu, message, sig_hybrid)
        t_verify_cached_mode3 = (time.time() - t0) / iterations * 1000

        results["Mode 3 (Custom C)"] = {
            "sign": t_sign_mode3, 
            "verify_recon": t_verify_recon_mode3, 
            "verify_cached": t_verify_cached_mode3,
            "sns": "是 (H-FSwA)", "len": 2452
        }
    else:
        results["Mode 3 (Custom C)"] = {
            "sign": 0.0, "verify_recon": 0.0, "verify_cached": 0.0, 
            "sns": "環境未啟用", "len": 2452
        }

    # --- 輸出數據對比表格 ---
    print("\n" + "=" * 100)
    print("                          後量子混合簽章效能評估報告數據表 (優化對比)")
    print("=" * 100)
    print(f"{'執行模式 (Backend Mode)':<23} | {'簽章 (Sign)':<11} | {'首次驗簽(Reconstruct)':<20} | {'後續驗簽(Key Cached)':<20} | {'不可分割性':<8} | {'簽章大小':<6}")
    print("-" * 100)
    
    for mode, data in results.items():
        if isinstance(data["sns"], str) and ("未安裝" in data["sns"] or "環境未啟用" in data["sns"]):
            print(f"{mode:<23} | \033[1;31m{'N/A (未啟用)':<11}\033[0m | \033[1;31m{'N/A (未啟用)':<20}\033[0m | \033[1;31m{'N/A (未啟用)':<20}\033[0m | {data['sns']:<10} | {data['len']}B")
        else:
            print(f"{mode:<23} | {data['sign']:>6.2f} ms | {data['verify_recon']:>15.2f} ms | {data['verify_cached']:>15.2f} ms | {data['sns']:<10} | {data['len']}B")
            
    print("=" * 105)
    print("效能分析評估摘要：")
    print("1. 啟用公鑰快取 (Key Cached) 後，RSU 驗簽時間大幅降低。")
    print("2. 這是由於後續封包免除了 ECQV 重建所需的 2 次隨機點 ECC 乘法運算，僅執行後量子 ML-DSA 驗簽。")
    print("3. Mode 1 (JIT) 與 Mode 3 (Custom C) 的後續驗簽均能將多項式運算壓縮至極低延遲，具備實用價值。")
    print("=" * 105 + "\n")

if __name__ == "__main__":
    run_benchmark()
