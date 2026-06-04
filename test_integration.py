import sys
import struct
import json
import time
import secrets
import os

# Ensure workspace is in Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from OBU.signature import (
    G, N, bytes_to_point, point_to_bytes,
    ecqv_obu_keygen_request, ecqv_ca_issue, ecqv_obu_recover_key,
    point_mul
)
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
import OBU.signature_oqs as sig_oqs
import RSU.parse as rsu_parse

def run_integration_test():
    print("==================================================")
    print("   STARTING MULTI-BACKEND INTEGRATION TESTS")
    print("==================================================")

    # 1. CA Initialization
    print("\n[CA] Generating CA Root Keys...")
    d_CA_ecc = secrets.randbelow(N - 1) + 1
    Q_CA_ecc = point_mul(d_CA_ecc, G)
    ca_ecc_pub_bytes = point_to_bytes(Q_CA_ecc, compressed=True)
    
    # Write CA key files for OBU/RSU setup load
    os.makedirs("CA/keys", exist_ok=True)
    os.makedirs("RSU/keys", exist_ok=True)
    with open("CA/keys/ca_ecc_pub.key", "wb") as f:
        f.write(ca_ecc_pub_bytes)
    with open("RSU/keys/ca_ecc_pub.key", "wb") as f:
        f.write(ca_ecc_pub_bytes)

    ca_pqc_pub, ca_pqc_priv = ML_DSA_44.keygen()
    print(f"CA ECC Public Key: {ca_ecc_pub_bytes.hex()} (33 bytes)")

    # 2. OBU Registration Request
    print("\n[OBU] Generating registration values...")
    obu_id = "AMB-217"
    k_obu, R_obu = ecqv_obu_keygen_request()
    R_obu_bytes = point_to_bytes(R_obu, compressed=True)
    
    # OBU generates its PQC keypair
    obu_pqc_pub, obu_pqc_priv = ML_DSA_44.keygen()
    print(f"OBU commitment R_obu: {R_obu_bytes.hex()} (33 bytes)")

    # 3. CA Issues ECQV implicit certificate
    print("\n[CA] Issuing Implicit Certificate...")
    expiry = int(time.time() + 31536000) # 1 year validity
    P_recon, s_ca = ecqv_ca_issue(R_obu, obu_id, expiry, obu_pqc_pub, d_CA_ecc)
    
    P_recon_bytes = point_to_bytes(P_recon, compressed=True)
    s_ca_bytes = s_ca.to_bytes(32, 'big')
    
    # Package certs
    ID_expiry = struct.pack('!8sQ', obu_id.encode('utf-8'), expiry)
    short_cert = ID_expiry + P_recon_bytes  # 16 + 33 = 49 bytes
    full_cert = ID_expiry + P_recon_bytes + obu_pqc_pub # 16 + 33 + 1312 = 1361 bytes

    # Save certs and keys to directories
    os.makedirs("OBU/keys", exist_ok=True)
    os.makedirs("OBU/cert", exist_ok=True)
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(s_ca_bytes)
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)
    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    with open(f"OBU/cert/{obu_id}_short_cert.bin", "wb") as f:
        f.write(short_cert)
    with open(f"OBU/cert/{obu_id}_full_cert.bin", "wb") as f:
        f.write(full_cert)

    # 4. OBU Recovers Private Key
    print("\n[OBU] Recovering ECC private key d_obu...")
    d_obu, Q_obu = ecqv_obu_recover_key(
        s_ca, P_recon, k_obu, obu_id, expiry, obu_pqc_pub, Q_CA_ecc
    )
    # Overwrite ecc_priv key file with the actual fully recovered private key
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(d_obu.to_bytes(32, 'big'))

    print("OBU ECC Private Key recovered successfully!")

    # ----------------------------------------------------
    # TEST 1: H-FSwA (Silithium) - Pure-Python (Mode 0)
    # ----------------------------------------------------
    print("\n" + "-" * 50)
    print(" TEST 1: H-FSwA (Silithium) - Pure-Python Mode")
    print("-" * 50)
    sig_oqs.ACTIVE_MODE = sig_oqs.MODE_PURE_PYTHON
    
    packet_full, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
    packet_short, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=True)

    print("[RSU] Verifying Packet (Full Cert Path)...")
    res_full = rsu_parse.parse_packet(packet_full)
    assert res_full is not None, "Full Cert verification failed"
    
    print("[RSU] Verifying Packet (Short Cert Path)...")
    res_short = rsu_parse.parse_packet(packet_short)
    assert res_short is not None, "Short Cert verification failed"

    # ----------------------------------------------------
    # TEST 2: H-FSwA (Silithium) - Numba JIT (Mode 1)
    # ----------------------------------------------------
    if sig_oqs.HAS_NUMBA:
        print("\n" + "-" * 50)
        print(" TEST 2: H-FSwA (Silithium) - Numba JIT Mode")
        print("-" * 50)
        sig_oqs.ACTIVE_MODE = sig_oqs.MODE_NUMBA_JIT
        
        packet_jit_full, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        packet_jit_short, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=True)

        print("[RSU] Verifying JIT Packet (Full Cert Path)...")
        res_jit_full = rsu_parse.parse_packet(packet_jit_full)
        assert res_jit_full is not None, "JIT Full Cert verification failed"
        
        print("[RSU] Verifying JIT Packet (Short Cert Path)...")
        res_jit_short = rsu_parse.parse_packet(packet_jit_short)
        assert res_jit_short is not None, "JIT Short Cert verification failed"
    else:
        print("\n[跳過] 本機未安裝 Numba，跳過 Numba JIT 模式測試。")

    # ----------------------------------------------------
    # TEST 3: liboqs Parallel Hybrid - (Mode 2)
    # ----------------------------------------------------
    if sig_oqs.HAS_LIBOQS:
        print("\n" + "-" * 50)
        print(" TEST 3: liboqs Parallel Hybrid C-Lib Mode")
        print("-" * 50)
        sig_oqs.ACTIVE_MODE = sig_oqs.MODE_LIBOQS_PARALLEL
        
        packet_p_full, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        packet_p_short, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=True)

        print("[RSU] Verifying Parallel Packet (Full Cert Path)...")
        res_p_full = rsu_parse.parse_packet(packet_p_full)
        assert res_p_full is not None, "Parallel Full Cert verification failed"
        
        print("[RSU] Verifying Parallel Packet (Short Cert Path)...")
        res_p_short = rsu_parse.parse_packet(packet_p_short)
        assert res_p_short is not None, "Parallel Short Cert verification failed"
    else:
        print("\n[跳過] 本機未安裝 liboqs，跳過 liboqs 並行模式測試。")

    # ----------------------------------------------------
    # TEST 4: H-FSwA (Silithium) - Custom C-Backend (Mode 3)
    # ----------------------------------------------------
    if sig_oqs.HAS_CUSTOM_C:
        print("\n" + "-" * 50)
        print(" TEST 4: H-FSwA (Silithium) - Custom C-Backend Mode")
        print("-" * 50)
        sig_oqs.ACTIVE_MODE = sig_oqs.MODE_CUSTOM_C
        
        packet_c_full, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=False)
        packet_c_short, _, _, _ = sig_oqs.master_sign(obu_id, known_RSU=True)

        print("[RSU] Verifying Custom C Packet (Full Cert Path)...")
        res_c_full = rsu_parse.parse_packet(packet_c_full)
        assert res_c_full is not None, "Custom C Full Cert verification failed"
        
        print("[RSU] Verifying Custom C Packet (Short Cert Path)...")
        res_c_short = rsu_parse.parse_packet(packet_c_short)
        assert res_c_short is not None, "Custom C Short Cert verification failed"
    else:
        print("\n[跳過] 未能加載客製 C NTT 動態庫，跳過客製 C 加速模式測試。")

    print("\n==================================================")
    print("   ALL MULTI-BACKEND TESTS COMPLETED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_integration_test()
