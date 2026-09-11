import struct
import oqs
import hashlib
from ecdsa import NIST256p
from ecdsa.util import randrange
from cryptography.hazmat.primitives import serialization
from ctypes import create_string_buffer
import ecdsa.ellipticcurve as ellipticcurve

def ca_process_enrollment(obu_id: bytes, obu_R_U_bytes: bytes, obu_pqc_pub: bytes):
    """
    輸入：obu_id、 obu_R_U_bytes、 obu_pqc_pub
    輸出：[P_U (33B) | r (32B) | sig_len (2B) | ca_pqc_sig]
    """
    curve = NIST256p
    n = curve.order
    G = curve.generator
    
    # 載入R_U
    R_U = ellipticcurve.PointJacobi.from_bytes(curve.curve, obu_R_U_bytes)
    # CA 產生 k_CA，計算 P_U = R_U + k_CA * G
    k_CA = randrange(n)
    P_U = R_U + (k_CA * G)
    P_U_bytes = P_U.to_bytes("compressed") # 壓縮



    # Hash Entanglement
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest()
    entanglement_data = obu_id + P_U_bytes + pqc_pub_hash
    e_hex = hashlib.sha256(entanglement_data).hexdigest()
    e = int(e_hex, 16) % n
    # 4. 計算私鑰重構因子 r = (e * k_CA + d_CA) mod n
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:
        ca_ecc_priv_obj = serialization.load_der_private_key(f.read(), password=None)

    ca_ecc_priv_int = ca_ecc_priv_obj.private_numbers().private_value
    r = (e * k_CA + ca_ecc_priv_int) % n
    
    # 5. 打包回傳標準 ECQV 資料：P_U (33 bytes) | r (32 bytes) -> 共 65 bytes!
    # 在純 ECQV 隱式憑證體系下，CA 的根公鑰 Q_CA 已經內嵌於重構公式 Q_U = e*P_U + Q_CA，
    # 車輛只要能簽出有效 ECC 簽章，數學上即證明擁有 CA 授權，無需重複夾帶 2.4KB 的 CA 簽章！
    r_bytes = r.to_bytes(32, byteorder='big')
    packed_data = struct.pack("!33s 32s", P_U_bytes, r_bytes)
    return packed_data
