import os
import secrets
from OBU.signature import G, N, point_mul, point_to_bytes
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44

def generate_ca_root_keys():
    # 1. 產生 CA 的 ECC 私鑰 (256-bit integer)
    ca_ecc_priv = secrets.randbelow(N - 1) + 1
    
    # 2. 產生 CA 的 ECC 公鑰點
    ca_ecc_pub_point = point_mul(ca_ecc_priv, G)
    ca_ecc_pub_bytes = point_to_bytes(ca_ecc_pub_point, compressed=True) # 33 bytes
    
    # 3. 產生 CA 的 PQC 金鑰對
    ca_pqc_pub, ca_pqc_priv = ML_DSA_44.keygen()
    
    return ca_ecc_pub_bytes, ca_ecc_priv, ca_pqc_pub, ca_pqc_priv

if __name__ == "__main__":
    os.makedirs("CA/keys", exist_ok=True)
    
    ca_ecc_pub, ca_ecc_priv, ca_pqc_pub, ca_pqc_priv = generate_ca_root_keys()

    with open("CA/keys/ca_ecc_pub.key", "wb") as f:
        f.write(ca_ecc_pub) # 33 bytes compressed point

    with open("CA/keys/ca_ecc_priv.key", "wb") as f:
        # Save private key as 32-byte big-endian integer
        f.write(ca_ecc_priv.to_bytes(32, 'big'))

    with open("CA/keys/ca_pqc_pub.key", "wb") as f:
        f.write(ca_pqc_pub)
    
    with open("CA/keys/ca_pqc_priv.key", "wb") as f:
        f.write(ca_pqc_priv)

    print("已成功生成 CA 的 ECC 和 PQC 金鑰對！")
    print(f"CA ECC公鑰長度: {len(ca_ecc_pub)} bytes (壓縮格式)")