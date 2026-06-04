import struct
import time
import os
from OBU.signature import G, N, bytes_to_point, point_to_bytes, ecqv_ca_issue

def issue_obu_certificate(obu_id, R_obu_bytes, pk_obu_pqc):
    try:
        # 1. 讀取 CA 的 ECC 私鑰 (32-byte big-endian integer)
        with open("CA/keys/ca_ecc_priv.key", "rb") as f:
            d_CA_ecc = int.from_bytes(f.read(), 'big')
            
        # 2. 解壓縮 OBU 的 R_obu 點
        R_obu = bytes_to_point(R_obu_bytes)
        
        # 3. 設定有效期限 (365天後)
        expiry = int(time.time() + 31536000)
        
        # 4. 計算 ECQV 重構點 P_recon 與 私鑰貢獻值 s_ca
        P_recon, s_ca = ecqv_ca_issue(R_obu, obu_id, expiry, pk_obu_pqc, d_CA_ecc)
        
        P_recon_bytes = point_to_bytes(P_recon, compressed=True) # 33 bytes
        s_ca_bytes = s_ca.to_bytes(32, 'big') # 32 bytes
        
        # 5. 打包憑證檔案 (.bin)
        # ID (8 bytes) + Expiry (8 bytes)
        ID_expiry = struct.pack('!8sQ', obu_id.encode('utf-8'), expiry)
        
        # 短憑證 (用於 RSU 已知 OBU PQC 公鑰的場景，節省空間)
        # 結構: ID_expiry (16) + P_recon (33) = 49 bytes
        short_cert = ID_expiry + P_recon_bytes
        
        # 完整憑證 (用於 RSU 需要現場學習 OBU PQC 公鑰的場景)
        # 結構: ID_expiry (16) + P_recon (33) + pk_obu_pqc (1312) = 1361 bytes
        full_cert = ID_expiry + P_recon_bytes + pk_obu_pqc

        os.makedirs("CA/cert", exist_ok=True)
        with open(f"CA/cert/{obu_id}_short_cert.bin", "wb") as f:
            f.write(short_cert)

        with open(f"CA/cert/{obu_id}_full_cert.bin", "wb") as f:
            f.write(full_cert)
        
        print(f"已成功核發 {obu_id} 的 ECQV 後量子隱式憑證！")
        print(f"重構點 P_recon: {len(P_recon_bytes)} bytes")
        print(f"短憑證大小: {len(short_cert)} bytes")
        print(f"完整憑證大小: {len(full_cert)} bytes")
        
        return s_ca_bytes, short_cert, full_cert
    except Exception as e:
        print(f"核發憑證失敗：{e}")
        return None, None, None