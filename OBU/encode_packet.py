import struct, oqs, json, hashlib
from ecdsa import SigningKey, NIST256p
from OBU.gen_payload import generate_bsm_payload
from ctypes import create_string_buffer

def gen_packet(obu_id, known_RSU=False):
    # 1. 生成 BSM Payload
    payload = generate_bsm_payload(obu_id)
    message = json.dumps(payload).encode('utf-8')

    # 2. 讀取 ECC 推導私鑰並進行簽章
    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "rb") as f:
        ecc_sk = SigningKey.from_der(f.read())
    ecc_sig = ecc_sk.sign(message, hashfunc=hashlib.sha256)

    # 3. 讀取 PQC 私鑰並進行 ML-DSA-44 簽章
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()
    with oqs.Signature("ML-DSA-44") as signer:
        signer.secret_key = create_string_buffer(pqc_priv, len(pqc_priv))
        pqc_sig = signer.sign(message)

    # 4. 讀取 ECQV 憑證
    with open(f"OBU/cert/{obu_id}_cert.bin", "rb") as f:
        cert_data = f.read()
    P_U_bytes = cert_data[:33]
    pqc_pub_len = struct.unpack('!H', cert_data[33:35])[0]
    obu_pqc_pub = cert_data[35 : 35 + pqc_pub_len]
    ca_pqc_sig_len = struct.unpack('!H', cert_data[35 + pqc_pub_len : 37 + pqc_pub_len])[0]
    ca_pqc_sig = cert_data[37 + pqc_pub_len : 37 + pqc_pub_len + ca_pqc_sig_len]
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest() # 計算 PQC 公鑰雜湊
    # 5. 組裝完整封包
    obu_id_raw = struct.pack('!8s', obu_id.encode('utf-8'))
    header_part = struct.pack('!H', len(message)) + message
    ecc_part = struct.pack('!B', len(ecc_sig)) + ecc_sig
    ecqv_cert_part = (
        obu_id_raw + 
        P_U_bytes + 
        pqc_pub_hash +
        struct.pack('!H', len(ca_pqc_sig)) + ca_pqc_sig
    )
    pqc_pub_part = struct.pack('!H', len(obu_pqc_pub)) + obu_pqc_pub
    pqc_sig_part = struct.pack('!H', len(pqc_sig)) + pqc_sig

    packet = header_part + ecc_part + ecqv_cert_part + pqc_pub_part + pqc_sig_part

    # 方便量化
    print(f"生成 ECQV 混合封包: \nPayload長度 = {len(message)} bytes\nECC簽章長度 = {len(ecc_sig)} bytes\nP_U重構點 = {len(P_U_bytes)} bytes\nPQC公鑰長度 = {len(obu_pqc_pub)} bytes\nPQC簽章長度 = {len(pqc_sig)} bytes\n總封包長度 = {len(packet)} bytes\n")
    return packet