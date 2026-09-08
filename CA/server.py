import json
import base64
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from CA.sign import issue_obu_certificate

CA_HOST = "0.0.0.0"  
CA_PORT = 5000       # CA 預設

class CARequestHandler(BaseHTTPRequestHandler):
    def _send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        # 提供下載公鑰
        if self.path == "/ca_keys":
            try:
                with open("CA/keys/ca_ecc_pub.key", "rb") as f:
                    ca_ecc_pub = f.read()
                with open("CA/keys/ca_pqc_pub.key", "rb") as f:
                    ca_pqc_pub = f.read()

                resp_data = {
                    "status": "success",
                    "ca_ecc_pub": base64.b64encode(ca_ecc_pub).decode("utf-8"),
                    "ca_pqc_pub": base64.b64encode(ca_pqc_pub).decode("utf-8")
                }
                self._send_json_response(200, resp_data)
            except Exception as e:
                self._send_json_response(500, {"status": "error", "message": str(e)})
        else:
            self._send_json_response(404, {"status": "error", "message": "Not Found"})

    def do_POST(self):
        # 接收+核發
        if self.path == "/issue_cert":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_body = self.rfile.read(content_length)
                req_json = json.loads(post_body.decode("utf-8"))

                obu_id = req_json.get("obu_id")
                ecc_pub_b64 = req_json.get("ecc_pub")
                pqc_pub_b64 = req_json.get("pqc_pub")

                if not (obu_id and ecc_pub_b64 and pqc_pub_b64):
                    self._send_json_response(400, {"status": "error", "message": "缺少必要參數"})
                    return

                # 解碼
                obu_ecc_pub = base64.b64decode(ecc_pub_b64)
                obu_pqc_pub = base64.b64decode(pqc_pub_b64)
                print(f"收到來自 {self.client_address[0]} 的憑證請求 (ID: {obu_id})")
                # 簽發
                short_cert, full_cert = issue_obu_certificate(obu_id, obu_ecc_pub, obu_pqc_pub)

                if short_cert is None or full_cert is None:
                    self._send_json_response(500, {"status": "error", "message": "核發憑證失敗"})
                    return

                resp_data = {
                    "status": "success",
                    "obu_id": obu_id,
                    "short_cert": base64.b64encode(short_cert).decode("utf-8"),
                    "full_cert": base64.b64encode(full_cert).decode("utf-8")
                }
                print(f"已核發 {obu_id} 憑證並回傳\n")
                self._send_json_response(200, resp_data)

            except Exception as e:
                print(f"CA 伺服器錯誤：{e}")
                self._send_json_response(500, {"status": "error", "message": str(e)})
        else:
            self._send_json_response(404, {"status": "error", "message": "Not Found"})

def run_ca_server(host=CA_HOST, port=CA_PORT):
    server_address = (host, port)
    httpd = HTTPServer(server_address, CARequestHandler)
    print(f"CA 伺服器啟動，監聽 {port}中")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nCA 伺服器已閉")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run_ca_server()
