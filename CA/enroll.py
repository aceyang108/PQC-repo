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
    # 算 r = (e * k_CA + d_CA) mod n
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:
        ca_ecc_priv_obj = serialization.load_der_private_key(f.read(), password=None)
    ca_ecc_priv_int = ca_ecc_priv_obj.private_numbers().private_value
    r = (e * k_CA + ca_ecc_priv_int) % n
    # CA 使用自己的 PQC 私鑰進行簽章
    with oqs.Signature("ML-DSA-44") as signer:
        with open("CA/keys/ca_pqc_priv.key", "rb") as f:
            ca_pqc_priv = f.read()
        signer.secret_key = create_string_buffer(ca_pqc_priv, len(ca_pqc_priv))
        ca_pqc_sig = signer.sign(entanglement_data)
    

    
    # 打包回傳
    r_bytes = r.to_bytes(32, byteorder='big')
    sig_len = len(ca_pqc_sig)
    packed_data = struct.pack(f"!33s 32s H {sig_len}s", P_U_bytes, r_bytes, sig_len, ca_pqc_sig)
    return packed_data
