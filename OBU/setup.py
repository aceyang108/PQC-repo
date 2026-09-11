import oqs, struct, os, argparse, json, hashlib
from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange
from cryptography.hazmat.primitives import serialization
from socket import *

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

CA_IP = os.getenv("CA_IP", "127.0.0.1")
CA_PORT = int(os.getenv("CA_PORT", 57217))
BUF_SIZE = 4096 

def recv_all(sock, count):
    """循環讀取至指定 count bytes"""
    buffer = b''
    while len(buffer) < count:
        to_read = min(count - len(buffer), BUF_SIZE)
        chunk = sock.recv(to_read)
        if not chunk:
            return None
        buffer += chunk
    return buffer

def generate_enrollment_request():
    """產生 OBU 的一次性隨機數 k_U 與請求點 R_U (33 bytes)"""
    curve = NIST256p
    G = curve.generator
    n = curve.order
    k_U = randrange(n)
    R_U = k_U * G
    R_U_bytes = R_U.to_bytes("compressed")
    return k_U, R_U_bytes

def obu_derive_key(obu_id_bytes: bytes, P_U_bytes: bytes, obu_pqc_pub: bytes, r: int, k_U: int):
    """根據雜湊糾纏值 e 重構出真正的 ECC 私鑰 d_U = (e * k_U + r) mod n"""
    curve = NIST256p
    n = curve.order
    pqc_pub_hash = hashlib.sha256(obu_pqc_pub).digest()
    entangled_data = obu_id_bytes + P_U_bytes + pqc_pub_hash
    e = int(hashlib.sha256(entangled_data).hexdigest(), 16) % n
    d_U = (e * k_U + r) % n
    return d_U

def request_cert(ca_ip, ca_port, obu_id_bytes, R_U_bytes, obu_pqc_pub):
    """透過 TCP 0x57 向 CA 發送 ECQV 註冊請求"""
    try:
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.settimeout(5)
        clientSocket.connect((ca_ip, ca_port))
        
        # 標頭格式：0x57 (1B) | ID (8B) | PQC公鑰長度 (2B) -> 共 11 bytes
        req_header = struct.pack('!B8sH', 0x57, obu_id_bytes, len(obu_pqc_pub))
        message = req_header + R_U_bytes + obu_pqc_pub

        clientSocket.sendall(message)

        recv_header = recv_all(clientSocket, 4)
        if not recv_header:
            clientSocket.close()
            return None
        resp_len = struct.unpack('!I', recv_header)[0]
        response = recv_all(clientSocket, resp_len)
        clientSocket.close()
        return response
    except Exception as e:
        print(f"TCP 連線 CA 失敗：{e}")
        return None

def setup(obu_id="AMB-217"):
    os.makedirs("OBU/keys", exist_ok=True)
    os.makedirs("OBU/cert", exist_ok=True)
    os.makedirs("OBU/json", exist_ok=True)

    # 確保 obu_id 為 8 bytes 固定長度
    obu_id_bytes = struct.pack('!8s', obu_id.encode('utf-8'))

    # 清空 RSU 記憶快取 (新金鑰重置)
    with open("OBU/json/saved_RSU.json", "w") as f:
        json.dump({}, f, indent=4)

    # 1. 產生 ECQV 暫時隨機數 k_U 與請求點 R_U
    print(f"[{obu_id}] 正在產生 ECQV 請求點 R_U (33 bytes)...")
    k_U, R_U_bytes = generate_enrollment_request()

    # 2. 準備 PQC 金鑰 (ML-DSA-44)
    print(f"[{obu_id}] 正在生成 ML-DSA-44 後量子金鑰對...")
    obu_pqc = oqs.Signature("ML-DSA-44")
    obu_pqc_pub = obu_pqc.generate_keypair()
    obu_pqc_priv = obu_pqc.export_secret_key()

    with open(f"OBU/keys/{obu_id}_pqc_pub.key", "wb") as f:
        f.write(obu_pqc_pub)
    with open(f"OBU/keys/{obu_id}_pqc_priv.key", "wb") as f:
        f.write(obu_pqc_priv)

    # 3. 向 CA 發送請求
    print(f"[{obu_id}] 正在向 CA ({CA_IP}:{CA_PORT}) 請求 ECQV 憑證...")
    response = request_cert(CA_IP, CA_PORT, obu_id_bytes, R_U_bytes, obu_pqc_pub)

    if response is None:
        print("憑證請求失敗！請確認 CA 伺服器是否已啟動 (python3 -m CA.listen)")
        return False

    # 4. 解析 CA 回應：P_U (33B) | r (32B) -> 總共僅 65 bytes
    P_U_bytes = response[:33]
    r_bytes = response[33:65]
    r_int = int.from_bytes(r_bytes, byteorder='big')

    # 5. 推導本地真正的 ECC 私鑰 d_U
    d_U = obu_derive_key(obu_id_bytes, P_U_bytes, obu_pqc_pub, r_int, k_U)
    obu_ecc_sk = SigningKey.from_secret_exponent(d_U, curve=NIST256p)

    with open(f"OBU/keys/{obu_id}_ecc_priv.key", "wb") as f:
        f.write(obu_ecc_sk.to_der())

    # 6. 打包並儲存純粹 ECQV 憑證：P_U (33B) | PQC公鑰長度 (2B) | PQC公鑰 (1312B)
    # 總體積僅 1347 bytes (相較舊版 4KB，大幅精簡！)
    ecqv_cert = struct.pack('!33sH', P_U_bytes, len(obu_pqc_pub)) + obu_pqc_pub
    with open(f"OBU/cert/{obu_id}_cert.bin", "wb") as f:
        f.write(ecqv_cert)

    print(f"[{obu_id}] 純粹 ECQV 憑證註冊成功！私鑰與精簡憑證已儲存完畢。")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("obu_id", nargs="?", default="AMB-217", help="緊急車輛的編號 (預設 AMB-217)")
    args = parser.parse_args()

    if setup(args.obu_id):
        print(f"{args.obu_id} 初始化完成！")
    else:
        print(f"{args.obu_id} 初始化失敗！")