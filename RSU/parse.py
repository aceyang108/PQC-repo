import struct, oqs, json, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

PQC_SIG_NAME = "ML-DSA-44"
def parse_header(header_bytes): # Header 格式：序列號(1) | 總分片數(1) | 訊息ID(2)
    try:
        seq_num, total_frags, msg_id = struct.unpack('!BBH', header_bytes)
    except struct.error as e:
        print(f"Header 解析失敗：{e}")
        return None, None, None
    return seq_num, total_frags, msg_id

# 從 F1 碎片中提取 BSM 訊息與 ECC 簽章並驗證
def verify_f1_ecc(f1_chunk):
    try:
        end = 2
        msg_len = int(struct.unpack('!H', f1_chunk[:end])[0])
        start = end
        end += msg_len
        payload_bytes = f1_chunk[start:end]

        # 提取 OBU ECC 簽章
        start = end
        end += 1
        ecc_sig_len = int(struct.unpack('!B', f1_chunk[start:end])[0])
        start = end
        end += ecc_sig_len
        ecc_sig = f1_chunk[start:end]

        # 提取憑證開頭的 ID 與公鑰長度
        start = end
        end += 16
        ID_expiry_bytes = f1_chunk[start:end]
        ID, expiry = struct.unpack('!8sQ', ID_expiry_bytes)
        obu_id_str = ID.decode('utf-8').rstrip('\x00')
        if time.time() > expiry:
            print(f"F1 憑證已過期 (ID: {obu_id_str})")
            return False, None, None
        start = end
        end += 3
        ecc_pub_len, pqc_pub_len = struct.unpack('!BH', f1_chunk[start:end])
        # 取得 OBU ECC 公鑰
        if ecc_pub_len == 0:
            with open(f"RSU/keys/{obu_id_str}_ecc_pub.key", "rb") as f:
                obu_ecc_pub = f.read()
        else:
            start = end
            end += ecc_pub_len
            obu_ecc_pub = f1_chunk[start:end]
        # 執行 ECC 簽章驗證
        obu_ecc_pub_obj = serialization.load_der_public_key(obu_ecc_pub)
        obu_ecc_pub_obj.verify(ecc_sig, payload_bytes, ec.ECDSA(hashes.SHA256()))
        # 檢查時間戳防重放攻擊
        f1_data = json.loads(payload_bytes)
        f1_latency = time.time() - f1_data.get("full_timestamp", 0)
        if f1_latency > 0.15:
            print(f"F1 訊息已過期 (延遲 {f1_latency*1000:.1f}ms > 150ms)，疑似重放攻擊")
            return False, obu_id_str, None

        return True, obu_id_str, payload_bytes
    except Exception as e:
        print(f"F1 ECC 簽章驗證失敗：{e}")
        return False, None, None

# 封包格式：Payload長度(2) | Payload | ECC簽章長度(1) | ECC簽章 | 憑證 | PQC簽章長度(2) | PQC簽章
# 憑證格式：| ID (8 bytes) | Expiry (8 bytes) | ECC公鑰長度 (1 byte) | PQC公鑰長度 (2 bytes) | ECC公鑰 (variable) | PQC公鑰 (variable) | 
# CA_ECC簽章長度 (1 byte) | CA_PQC簽章長度 (2 bytes) | CA_ECC簽章 (variable) | CA_PQC簽章 (variable) |




def parse_packet(packet):
    # 提取 Payload 長度與內容
    end = 2
    msg_len = int(struct.unpack('!H', packet[:end])[0])

    start = end
    end += msg_len
    payload_bytes = packet[start:end]
    start = end
    end += 1
    obu_ecc_sig_len = int(struct.unpack('!B', packet[start:end])[0])
    start = end
    end += obu_ecc_sig_len
    obu_ecc_sig = packet[start:end]
    start = end
    end += 16
    ID_expiry_bytes = packet[start:end]
    ID, expiry = struct.unpack('!8sQ', ID_expiry_bytes)
    obu_id_str = ID.decode('utf-8').rstrip('\x00')
    if time.time() > expiry:
        print(f"憑證已過期 (ID: {obu_id_str}, Expiry: {time.ctime(expiry)})")
        return None

    # 提取ECC公鑰長度 + PQC公鑰長度
    start = end
    end += 3
    ecc_pub_len, pqc_pub_len = struct.unpack('!BH', packet[start:end])
    if ecc_pub_len == 0:
        with open(f"RSU/keys/{obu_id_str}_ecc_pub.key", "rb") as f:
            obu_ecc_pub = f.read()
    else:
        start = end
        end += ecc_pub_len
        obu_ecc_pub = packet[start:end]
        # 收到 full_cert 存入本地Cache
        with open(f"RSU/keys/{obu_id_str}_ecc_pub.key", "wb") as f:
            f.write(obu_ecc_pub)

    # 提取OBU PQC公鑰
    if pqc_pub_len == 0:
        with open(f"RSU/keys/{obu_id_str}_pqc_pub.key", "rb") as f:
            obu_pqc_pub = f.read()
    else:
        start = end
        end += pqc_pub_len
        obu_pqc_pub = packet[start:end]
        with open(f"RSU/keys/{obu_id_str}_pqc_pub.key", "wb") as f:
            f.write(obu_pqc_pub)

    # TBSC內容：ID_expiry + obu_ecc_pub + obu_pqc_pub
    tbs_content = ID_expiry_bytes + obu_ecc_pub + obu_pqc_pub
    start = end
    end += 3
    ca_ecc_sig_len, ca_pqc_sig_len = struct.unpack('!BH', packet[start:end])
    start = end
    end += ca_ecc_sig_len
    ca_ecc_sig = packet[start:end]
    start = end
    end += ca_pqc_sig_len
    ca_pqc_sig = packet[start:end]
    # 驗證憑證有效性 (CA 雙重簽章)
    if not verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content):
        print("憑證驗證失敗，拒絕通行。")
        return None

    start = end
    end += 2
    obu_pqc_sig_len = int(struct.unpack('!H', packet[start:end])[0])
    start = end
    end += obu_pqc_sig_len
    obu_pqc_sig = packet[start:end]
    obu_ecc_pub_obj = serialization.load_der_public_key(obu_ecc_pub)
    passed = verify_obu_sig(obu_ecc_pub_obj, obu_pqc_pub, obu_ecc_sig, obu_pqc_sig, payload_bytes)

    if passed:
        return json.loads(payload_bytes) 
    else:
        return None  # 驗證失敗

def verify_cert(ca_ecc_sig, ca_pqc_sig, tbs_content):
    ecc_ok, pqc_ok = False, False

    # 驗證ECC
    try:
        with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
            ca_ecc_pub_data = f.read()
        ca_ecc_pub = serialization.load_der_public_key(ca_ecc_pub_data)
        ca_ecc_pub.verify(ca_ecc_sig, tbs_content, ec.ECDSA(hashes.SHA256()))  
        print("CA ECC 簽章驗證成功")
        ecc_ok = True
    except Exception as e:
        print(f"CA ECC 簽章驗證失敗：{e}")
        print("CA 混合簽章驗證失敗")
        return False

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        with open("RSU/keys/ca_pqc_pub.key", "rb") as f:
            ca_pqc_pub = f.read() 
        pqc_ok = verifier.verify(tbs_content, ca_pqc_sig, ca_pqc_pub) 
        if pqc_ok:
            print("CA PQC 簽章驗證成功")
        else:
            print("CA PQC 簽章驗證失敗")



    if ecc_ok and pqc_ok:
        print("CA 混合簽章驗證成功")
        return True
    else:
        print("CA 混合簽章驗證失敗")
        return False

def verify_obu_sig(ecc_pub, pqc_pub, ecc_sig, pqc_sig, payload_bytes):
    # 驗證ECC
    try:
        ecc_pub.verify(ecc_sig, payload_bytes, ec.ECDSA(hashes.SHA256()))  
        print("OBU ECC 簽章驗證成功")
        ecc_ok = True
    except Exception as e:
        print(f"OBU ECC 簽章驗證失敗：{e}")
        ecc_ok = False

    # 驗證PQC
    with oqs.Signature(PQC_SIG_NAME) as verifier:
        pqc_ok = verifier.verify(payload_bytes, pqc_sig, pqc_pub)  
        if pqc_ok:
            print("OBU PQC 簽章驗證成功")
        else:
            print("OBU PQC 簽章驗證失敗")
    if ecc_ok and pqc_ok:
        print("OBU 混合簽章驗證成功")
        return True
    else:
        print("OBU 混合簽章驗證失敗")
        return False