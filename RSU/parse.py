import struct, oqs, json, time, hashlib, os
from collections import OrderedDict
from ecdsa import NIST256p, VerifyingKey
import ecdsa.ellipticcurve as ellipticcurve
from cryptography.hazmat.primitives import serialization

PQC_SIG_NAME = "ML-DSA-44"

# 純記憶體 LRU 快取：{ (obu_id, P_U_bytes): vk }
# 容量上限設為 500 台車 (僅佔用約 150 KB RAM)，徹底消除內存耗竭 DoS
MEMORY_KEY_CACHE = OrderedDict()
PQC_PUB_CACHE = OrderedDict()
MAX_CACHE_SIZE = 500

def update_key_cache(cache_key, vk):
    """驗證通過後才寫入：更新並維護 LRU 隊列上限"""
    MEMORY_KEY_CACHE[cache_key] = vk
    MEMORY_KEY_CACHE.move_to_end(cache_key)
    if len(MEMORY_KEY_CACHE) > MAX_CACHE_SIZE:
        MEMORY_KEY_CACHE.popitem(last=False)

def update_pqc_pub_cache(obu_id_raw, pqc_pub):
    """記憶體快取車輛的 PQC 公鑰 (1312 bytes)"""
    PQC_PUB_CACHE[obu_id_raw] = pqc_pub
    PQC_PUB_CACHE.move_to_end(obu_id_raw)
    if len(PQC_PUB_CACHE) > MAX_CACHE_SIZE:
        PQC_PUB_CACHE.popitem(last=False)

def parse_header(header_bytes):
    """Header (4 bytes)：序號(1) | 總分片數(1) | 訊息ID(2)"""
    try:
        seq_num, total_frags, msg_id = struct.unpack('!BBH', header_bytes)
    except struct.error as e:
        print(f"Header 解析失敗：{e}")
        return None, None, None
    return seq_num, total_frags, msg_id

def reconstruct_obu_pubkey(obu_id_bytes: bytes, P_U_bytes: bytes, pqc_pub_hash: bytes):
    """
    ECQV 公鑰重構公式：
      1. e = SHA256(ID || P_U || pqc_pub_hash) mod n
      2. Q_U = e * P_U + Q_CA
    """
    curve = NIST256p
    n = curve.order

    # 1. 讀取 CA ECC 根公鑰 Q_CA
    with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
        ca_ecc_pub_obj = serialization.load_der_public_key(f.read())
    ca_numbers = ca_ecc_pub_obj.public_numbers()
    Q_CA = ellipticcurve.PointJacobi(curve.curve, ca_numbers.x, ca_numbers.y, 1)

    # 2. 算糾纏值 e
    entangled_data = obu_id_bytes + P_U_bytes + pqc_pub_hash
    e = int(hashlib.sha256(entangled_data).hexdigest(), 16) % n

    # 3. 執行橢圓曲線乘加運算
    P_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, P_U_bytes)
    Q_U = (e * P_U) + Q_CA

    return VerifyingKey.from_public_point(Q_U, curve=NIST256p)

def verify_f1_ecc(f1_chunk):
    """
    從 F1 碎片中提取分片承諾雜湊清單、BSM 訊息與 ECC 簽章並進行快速驗證
    F1 佈局：
      num_hashes (1B) | [H_2 (32B)] | [H_3 (32B)]... |
      msg_len (2B) | msg | ecc_sig_len (1B) | ecc_sig | ID (8B) | P_U (33B) | pqc_pub_hash (32B)
    """
    try:
        # 1. 提取後續分片雜湊承諾 (Fragment Commitment)
        start = 0
        num_hashes = int(struct.unpack('!B', f1_chunk[:1])[0])
        start += 1
        expected_hashes = {}
        for idx in range(num_hashes):
            seq = idx + 2
            expected_hashes[seq] = f1_chunk[start : start + 32]
            start += 32

        # 2. 提取 Payload
        end = start + 2
        msg_len = int(struct.unpack('!H', f1_chunk[start:end])[0])
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

        # 提取 ECQV 輕量憑證開頭：ID (8B) | P_U (33B) | pqc_pub_hash (32B)
        start = end
        end += 8
        obu_id_raw = f1_chunk[start:end]
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')

        start = end
        end += 33
        P_U_bytes = f1_chunk[start:end]

        start = end
        end += 32
        pqc_pub_hash = f1_chunk[start:end]

        # 1. 優先查純記憶體快取 (0 ns，無磁碟 I/O)
        cache_key = (obu_id_raw, P_U_bytes) #複合金鑰
        if cache_key in MEMORY_KEY_CACHE:
            vk = MEMORY_KEY_CACHE[cache_key]
            MEMORY_KEY_CACHE.move_to_end(cache_key) # 刷新 LRU 活躍度
        else:
            # 未命中則現場從 33-byte P_U 自癒重構 (徹底消除狀態失步)
            vk = reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_pub_hash)

        # 先驗證簽章！
        if not vk.verify(ecc_sig, payload_bytes, hashfunc=hashlib.sha256):
            return False, obu_id_str, None, None, None

        # 3. 簽章通過才安全寫入
        update_key_cache(cache_key, vk)

        # 檢查時間戳防重放攻擊 (150ms)
        f1_data = json.loads(payload_bytes.decode('utf-8'))
        f1_latency = time.time() - f1_data.get("full_timestamp", 0)
        if f1_latency > 0.15:
            print(f"F1 訊息已過期 (延遲 {f1_latency*1000:.1f}ms > 150ms)，疑似重放攻擊")
            return False, obu_id_str, None, None, None

        # raw_f1_data 為扣除開頭承諾標頭後的純粹分片資料 (供後續組裝)
        raw_f1_data = f1_chunk[1 + num_hashes * 32 :]
        return True, obu_id_str, payload_bytes, expected_hashes, raw_f1_data

    except Exception as e:
        print(f"F1 ECC 簽章驗證失敗：{e}")
        return False, None, None, None, None

def parse_packet(packet):
    """
    完整封包解析與驗證：
    封包格式：
      msg_len (2B) | payload | ecc_sig_len (1B) | ecc_sig |
      ID (8B) | P_U (33B) | pqc_pub_hash (32B) | ca_pqc_sig_len (2B) | ca_pqc_sig |
      pqc_pub_len (2B) | pqc_pub | pqc_sig_len (2B) | pqc_sig
    """
    try:
        end = 2
        msg_len = int(struct.unpack('!H', packet[:end])[0])
        start = end
        end += msg_len
        payload_bytes = packet[start:end]

        # ECC 簽章
        start = end
        end += 1
        obu_ecc_sig_len = int(struct.unpack('!B', packet[start:end])[0])
        start = end
        end += obu_ecc_sig_len
        obu_ecc_sig = packet[start:end]

        # ECQV 憑證欄位
        start = end
        end += 8
        obu_id_raw = packet[start:end]
        obu_id_str = obu_id_raw.decode('utf-8').rstrip('\x00')
        start = end
        end += 33
        P_U_bytes = packet[start:end]
        start = end
        end += 32
        pqc_pub_hash = packet[start:end]
        # 提取 OBU 的 PQC 公鑰 (若 pqc_pub_len == 0 則為 Short 模式，由記憶體快取還原)
        start = end
        end += 2
        pqc_pub_len = int(struct.unpack('!H', packet[start:end])[0])
        
        if pqc_pub_len == 0:
            # 二次通訊 (Short 模式)：從記憶體快取還原 PQC 公鑰
            if obu_id_raw in PQC_PUB_CACHE:
                obu_pqc_pub = PQC_PUB_CACHE[obu_id_raw]
                PQC_PUB_CACHE.move_to_end(obu_id_raw)
            else:
                print(f"收到 Short 封包但記憶體查無快取公鑰 (車輛: {obu_id_str})，等待下一包 Full 封包自癒")
                return None
        else:
            # 首次通訊 (Full 模式)：接收完整 1312B 公鑰
            start = end
            end += pqc_pub_len
            obu_pqc_pub = packet[start:end]

            # 1. 雜湊綁定檢查 (防 DoS 注入攻擊)：檢查完整公鑰是否吻合 F1 裡的 pqc_pub_hash
            if hashlib.sha256(obu_pqc_pub).digest() != pqc_pub_hash:
                print(f"PQC 公鑰雜湊不符，疑似偽造公鑰攻擊！(車輛: {obu_id_str})")
                return None

            # 驗證通過，安全存入記憶體快取 (Verify-then-Cache)
            update_pqc_pub_cache(obu_id_raw, obu_pqc_pub)

        # 2. 提取 OBU 的 PQC 簽章
        start = end
        end += 2
        obu_pqc_sig_len = int(struct.unpack('!H', packet[start:end])[0])
        start = end
        end += obu_pqc_sig_len
        obu_pqc_sig = packet[start:end]

        # 3. 驗證 OBU 的 PQC 簽章 (ML-DSA-44 抗量子安全)
        with oqs.Signature(PQC_SIG_NAME) as verifier:
            if not verifier.verify(payload_bytes, obu_pqc_sig, obu_pqc_pub):
                print(f"OBU 後量子簽章驗證失敗！(車輛: {obu_id_str})")
                return None

        # 驗證 OBU 的 ECC 簽章
        cache_key = (obu_id_raw, P_U_bytes)
        if cache_key in MEMORY_KEY_CACHE:
            vk = MEMORY_KEY_CACHE[cache_key]
            MEMORY_KEY_CACHE.move_to_end(cache_key)
        else:
            vk = reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_pub_hash)
        if not vk.verify(obu_ecc_sig, payload_bytes, hashfunc=hashlib.sha256):
            print(f"OBU ECC 簽章驗證失敗(車輛: {obu_id_str})")
            return None
        update_key_cache(cache_key, vk)

        print(f"ECQV + ML-DSA-44 驗證全部通過")
        return json.loads(payload_bytes.decode('utf-8'))

    except Exception as e:
        print(f"封包解析失敗：{e}")
        return None