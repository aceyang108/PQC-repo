import socket, time, json, os, argparse
from OBU.encode_packet import gen_packet
from OBU.fragment import send_fragment

# 配置參數
OBU_ID = "AMB-217"  # 車輛 ID，最多8字元
RSU_IP = "127.0.0.1" 
RSU_PORT = 5005
FREQUENCY = 5  # 發送頻率 (秒)

# 用計數器的方式取得ID
current_msg_id = 0
saved_RSU = {}

def get_next_id():
    global current_msg_id
    current_msg_id = (current_msg_id + 1) % 65536
    return current_msg_id

def check_RSU():
    rsu_key = f"{RSU_IP}:{RSU_PORT}"
    if rsu_key in saved_RSU:
        # 快取有效期為 15 秒 (符合緊急車輛通過單一路口之時間跨度)
        if time.time() - saved_RSU[rsu_key] < 15.0:
            return True
        else:
            del saved_RSU[rsu_key]
    return False

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_heartbeat(obu_id, frequency):
    print(f"--- OBU {obu_id} 啟動，目標 RSU {RSU_IP}:{RSU_PORT}，發送頻率: {frequency}s ---")
    sock.settimeout(0.3) # 每次廣播後等待 300ms 監聽 RSU 下行之 SSM ACK
    try:
        while True:
            is_known = check_RSU()
            packet = gen_packet(obu_id, known_RSU=is_known)
            send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))

            # 監聽並解析 RSU 下行的 SAE J2735 SSM (msgID=30)
            try:
                ack_data, _ = sock.recvfrom(2048)
                ack_json = json.loads(ack_data.decode('utf-8'))
                if ack_json.get("msgID") == 30: # SSM (Signal Status Message)
                    status_list = ack_json.get("status", [{}])[0].get("sigStatus", [])
                    for item in status_list:
                        req_entity = item.get("requester", {}).get("id", {}).get("entityID")
                        if req_entity == obu_id and item.get("status") == 4: # 4 = granted
                            rsu_key = f"{RSU_IP}:{RSU_PORT}"
                            if not is_known:
                                print(f"【收到 RSU SSM 綠燈核准回條】首次建聯放行！切換為 Short 模式。\n")
                            saved_RSU[rsu_key] = time.time()
                            break
            except socket.timeout:
                if not is_known:
                    print(f"[提示] 未收到 RSU 的 SSM 核准回條 (可能空中掉包)，下一週期將保持 Full 模式重試。\n")
                else:
                    # 在 Short 模式下若收不到回條，代表 RSU 可能重啟或快取丟失，主動降級回 Full 模式！
                    rsu_key = f"{RSU_IP}:{RSU_PORT}"
                    if rsu_key in saved_RSU:
                        del saved_RSU[rsu_key]
                    print(f"[警告] Short 模式未收到 RSU 回條 (RSU 可能快取丟失)，立即降級回 Full 模式重試！\n")

            time.sleep(frequency)
    except KeyboardInterrupt:
        print("\nOBU 已停止發送")
    finally:
        with open("OBU/json/saved_RSU.json", "w") as f:
            json.dump(saved_RSU, f, indent=4)
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OBU 緊急車輛廣播發送端")
    parser.add_argument("obu_id", nargs="?", default="AMB-217", help="車輛 ID (預設: AMB-217)")
    parser.add_argument("frequency", nargs="?", type=float, default=5.0, help="發送頻率 (秒，預設: 5.0)")
    args = parser.parse_args()

    try:
        with open("OBU/json/saved_RSU.json", "r") as f:
            saved_RSU = json.load(f)
    except Exception:
        saved_RSU = {}

    send_heartbeat(args.obu_id, args.frequency)