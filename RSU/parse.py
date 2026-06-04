import struct
import json
import time
import os
from OBU.signature import (
    bytes_to_point, point_to_bytes,
    ecqv_rsu_reconstruct_public_key, h_fswa_verify
)

# Header 格式：序列號(1) | 總分片數(1) | 訊息ID(2)
def parse_header(header_bytes):
    try:
        seq_num, total_frags, msg_id = struct.unpack('!BBH', header_bytes)
    except struct.error as e:
        print(f"Header 解析失敗：{e}")
        return None, None, None
    return seq_num, total_frags, msg_id

# 封包格式：Payload長度(2) | Payload | 憑證 (short=49 bytes, full=1361 bytes) | Hybrid簽章 (2452 bytes)
# 憑證格式：| ID (8 bytes) | Expiry (8 bytes) | P_recon (33 bytes) | [pk_obu_pqc (1312 bytes) - 僅full憑證]
def parse_packet(packet):
    try:
        # 1. 提取 Payload 長度
        msg_len = int(struct.unpack('!H', packet[:2])[0])

        # 2. 提取 Payload 內容 (bytes)
        payload_bytes = packet[2 : 2 + msg_len]

        # 3. 判斷簽章樣式 (H-FSwA=2452 還是 Parallel=2484)
        remaining_len = len(packet) - 2 - msg_len
        if remaining_len >= 2484 and (remaining_len - 2484 == 49 or remaining_len - 2484 == 1361):
            sig_len = 2484
            is_parallel = True
        else:
            sig_len = 2452
            is_parallel = False

        sig_hybrid = packet[-sig_len:]

        # 4. 提取憑證位元組 (介於 Payload 和 簽章之間)
        cert_bytes = packet[2 + msg_len : -sig_len]
        cert_len = len(cert_bytes)

        # 5. 解析憑證欄位 (ID & Expiry & P_recon)
        obu_id_bytes, expiry = struct.unpack('!8sQ', cert_bytes[:16])
        obu_id = obu_id_bytes.decode('utf-8').strip('\x00')
        
        # 檢查憑證有效期限
        if time.time() > expiry:
            print(f"憑證已過期 (ID: {obu_id}, Expiry: {time.ctime(expiry)})")
            return None

        # 提取重構點 P_recon (33 bytes)
        P_recon_bytes = cert_bytes[16:49]
        P_recon = bytes_to_point(P_recon_bytes)

        # 6. 取得 OBU PQC 公鑰
        if cert_len > 49:
            # Full 憑證直接包含 PQC 公鑰 (1312 bytes)
            pk_obu_pqc = cert_bytes[49:]
            # 並快取到本地 keys 目錄
            os.makedirs("RSU/keys", exist_ok=True)
            with open(f"RSU/keys/{obu_id}_pqc_pub.key", "wb") as f:
                f.write(pk_obu_pqc)
        else:
            # Short 憑證則從本地 keys 快取讀取 PQC 公鑰
            try:
                with open(f"RSU/keys/{obu_id}_pqc_pub.key", "rb") as f:
                    pk_obu_pqc = f.read()
            except FileNotFoundError:
                print(f"未找到 OBU PQC 金鑰快取 (ID: {obu_id})，必須先發送 Full 憑證！")
                return None

        # 7. 載入 CA ECC 公鑰
        with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
            Q_CA_ecc_bytes = f.read()
        Q_CA_ecc = bytes_to_point(Q_CA_ecc_bytes)

        # 8. 優先從本地快取讀取已重建的 OBU ECC 公鑰 Q_obu，避免重複進行高能耗的點乘法
        cached_ecc_pub_path = f"RSU/keys/{obu_id}_ecc_pub.key"
        if os.path.exists(cached_ecc_pub_path):
            with open(cached_ecc_pub_path, "rb") as f:
                Q_obu_bytes = f.read()
            Q_obu = bytes_to_point(Q_obu_bytes)
        else:
            # 若無快取，進行 ECQV 隱式重建
            Q_obu = ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, pk_obu_pqc, Q_CA_ecc)
            # 將重建好的公鑰快取起來，供後續封包直接使用
            os.makedirs("RSU/keys", exist_ok=True)
            with open(cached_ecc_pub_path, "wb") as f:
                f.write(point_to_bytes(Q_obu, compressed=True))

        # 9. 簽章驗證
        print(f"ECQV 憑證驗證：成功推導 OBU 公鑰！")
        if is_parallel:
            from OBU.signature_oqs import liboqs_parallel_verify
            passed = liboqs_parallel_verify(obu_id, Q_obu, pk_obu_pqc, payload_bytes, sig_hybrid)
            sig_name = "liboqs Parallel"
        else:
            passed = h_fswa_verify(pk_obu_pqc, Q_obu, payload_bytes, sig_hybrid)
            sig_name = "H-FSwA (Silithium)"

        if passed:
            print(f"{sig_name} 混合簽章驗證成功！")
            return json.loads(payload_bytes)
        else:
            print(f"{sig_name} 混合簽章驗證失敗！")
            return None
    except Exception as e:
        print(f"封包解析與驗證出錯：{e}")
        return None