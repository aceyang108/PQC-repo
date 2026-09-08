import oqs
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from OBU.main import OBU_ID

# CA 伺服器設定
CA_IP = "127.0.0.1"
CA_PORT = 5000

# 向遠端 CA 發送請求取得憑證
def request_remote_certificate(obu_id, obu_ecc_pub_bytes, obu_pqc_pub, ca_ip=CA_IP, ca_port=CA_PORT):
    import urllib.request
    import base64
    url = f"http://{ca_ip}:{ca_port}/issue_cert"
    payload = {
        "obu_id": obu_id,
        "ecc_pub": base64.b64encode(obu_ecc_pub_bytes).decode("utf-8"),
        "pqc_pub": base64.b64encode(obu_pqc_pub).decode("utf-8")
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        short_cert = base64.b64decode(res_data["short_cert"])
        full_cert = base64.b64decode(res_data["full_cert"])
        return short_cert, full_cert

def setup(obu_id):
    # 清空原有內容
    with open("OBU/json/saved_RSU.json", "w") as f:
        empty_data = {}
        json.dump(empty_data, f, indent=4)

    # 準備 ECC 金鑰
    obu_ecc_priv = ec.generate_private_key(ec.SECP256R1())
    obu_ecc_pub_bytes = obu_ecc_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # 準備 PQC 金鑰 (ML-DSA-44)
    obu_pqc = oqs.Signature("ML-DSA-44")
    obu_pqc_pub = obu_pqc.generate_keypair()
    obu_pqc_priv = obu_pqc.export_secret_key()

    with open(f"OBU/keys/{obu_id}_ecc_pub.key", "wb") as f:
        f.write(obu_ecc_pub_bytes)

    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(obu_ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # 專題演示建議先不加密
        ))

    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)

    # 向 CA 申請憑證 (若遠端沒開就用本機的 CA)
    try:
        print(f"向 CA ({CA_IP}:{CA_PORT}) 請求憑證...")
        short_cert, full_cert = request_remote_certificate(obu_id, obu_ecc_pub_bytes, obu_pqc_pub)
        print(f"成功取得 {obu_id} 憑證！")
    except Exception:
        print("遠端 CA 未連線，改用本地 CA 簽發...")
        from CA.sign import issue_obu_certificate
        short_cert, full_cert = issue_obu_certificate(obu_id, obu_ecc_pub_bytes, obu_pqc_pub)

    if short_cert is not None:
        with open(f"OBU/cert/{obu_id}_short_cert.bin", "wb") as f:
            f.write(short_cert)
    if full_cert is not None:
        with open(f"OBU/cert/{obu_id}_full_cert.bin", "wb") as f:
            f.write(full_cert)

    return short_cert, full_cert
if __name__ == "__main__":
    if setup(OBU_ID):
        print(f"{OBU_ID} 的金鑰和憑證已成功生成！")
    else:
        print(f"{OBU_ID} 的金鑰和憑證生成失敗！")