import json
import base64
import os
import urllib.request

CA_IP = "127.0.0.1"
CA_PORT = 5000

# 下載 CA 的 ECC 和 PQC 公鑰
def fetch_ca_keys(ca_ip=CA_IP, ca_port=CA_PORT):
    url = f"http://{ca_ip}:{ca_port}/ca_keys"
    os.makedirs("RSU/keys", exist_ok=True)
    try:
        print(f"向 CA 伺服器 ({ca_ip}:{ca_port}) 取得公鑰...")
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        ca_ecc_pub = base64.b64decode(data["ca_ecc_pub"])
        ca_pqc_pub = base64.b64decode(data["ca_pqc_pub"])
        with open("RSU/keys/ca_ecc_pub.key", "wb") as f:
            f.write(ca_ecc_pub)
        with open("RSU/keys/ca_pqc_pub.key", "wb") as f:
            f.write(ca_pqc_pub)
        print("成功配置CA公鑰！")
        return True

    except Exception:
        # 如果遠端沒開，改從本地複製 
        if os.path.exists("CA/keys/ca_ecc_pub.key") and os.path.exists("CA/keys/ca_pqc_pub.key"):
            print("遠端 CA 未連線，改從本地 CA/keys/ 複製...")
            with open("CA/keys/ca_ecc_pub.key", "rb") as f_in, open("RSU/keys/ca_ecc_pub.key", "wb") as f_out:
                f_out.write(f_in.read())
            with open("CA/keys/ca_pqc_pub.key", "rb") as f_in, open("RSU/keys/ca_pqc_pub.key", "wb") as f_out:
                f_out.write(f_in.read())
            print("本地複製完成")
            return True
        else:
            print("找不到 CA 公鑰，請先生成金鑰或啟動 CA 伺服器。")
            return False

if __name__ == "__main__":
    fetch_ca_keys()
