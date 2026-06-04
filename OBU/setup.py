import os
import json
import struct
from OBU.signature import (
    G, N, bytes_to_point, point_to_bytes, point_mul,
    ecqv_obu_keygen_request, ecqv_obu_recover_key
)
from CA.sign import issue_obu_certificate
from OBU.main import OBU_ID
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44

def setup(obu_id):
    # 清空與記憶 RSU 相關的舊資料
    os.makedirs("OBU/json", exist_ok=True)
    with open("OBU/json/saved_RSU.json", "w") as f:
        empty_data = {}
        json.dump(empty_data, f, indent=4)

    # 1. OBU 生成 ECQV 註冊用的隨機數 k_obu 和承諾點 R_obu
    k_obu, R_obu = ecqv_obu_keygen_request()
    R_obu_bytes = point_to_bytes(R_obu, compressed=True) # 33 bytes

    # 2. OBU 生成 PQC 金鑰對 (ML-DSA-44)
    obu_pqc_pub, obu_pqc_priv = ML_DSA_44.keygen()

    # 3. 呼叫 CA 核發隱式憑證
    s_ca_bytes, short_cert, full_cert = issue_obu_certificate(obu_id, R_obu_bytes, obu_pqc_pub)
    if s_ca_bytes is None:
        print("CA 核發憑證失敗！")
        return False

    # 4. OBU 載入 CA ECC 公鑰 Q_CA_ecc
    with open("CA/keys/ca_ecc_pub.key", "rb") as f:
        Q_CA_ecc_bytes = f.read()
    Q_CA_ecc = bytes_to_point(Q_CA_ecc_bytes)

    # 5. 解析 CA 回傳的憑證資料，以還原 OBU ECC 私鑰 d_obu
    # short_cert 格式: | ID (8 bytes) | Expiry (8 bytes) | P_recon (33 bytes) |
    expiry = struct.unpack('!Q', short_cert[8:16])[0]
    P_recon_bytes = short_cert[16:49]
    P_recon = bytes_to_point(P_recon_bytes)
    
    s_ca = int.from_bytes(s_ca_bytes, 'big')

    # 還原 OBU 的 ECC 私鑰 d_obu 與 公鑰點 Q_obu
    d_obu, Q_obu = ecqv_obu_recover_key(
        s_ca, P_recon, k_obu, obu_id, expiry, obu_pqc_pub, Q_CA_ecc
    )
    
    Q_obu_bytes = point_to_bytes(Q_obu, compressed=True) # 33 bytes

    # 6. 寫入金鑰檔案
    os.makedirs("OBU/keys", exist_ok=True)
    os.makedirs("OBU/cert", exist_ok=True)

    with open(f"OBU/keys/{obu_id}_ecc_pub.key", "wb") as f:
        f.write(Q_obu_bytes) # 33 bytes compressed point

    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(d_obu.to_bytes(32, 'big')) # 32 bytes scalar

    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)

    with open(f"OBU/cert/{obu_id}_short_cert.bin", "wb") as f:
        f.write(short_cert)
        
    with open(f"OBU/cert/{obu_id}_full_cert.bin", "wb") as f:
        f.write(full_cert)

    return True

if __name__ == "__main__":
    if setup(OBU_ID):
        print(f"{OBU_ID} 的 ECQV 金鑰與隱式憑證已成功生成與還原！")
    else:
        print(f"{OBU_ID} 的金鑰和憑證生成失敗！")