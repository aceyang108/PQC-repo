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
        return True
    saved_RSU[rsu_key] = time.time()
    print(f"已記憶 RSU：{rsu_key}")
    return False

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_heartbeat(obu_id, frequency):
    print(f"--- OBU {obu_id} 啟動，目標 RSU {RSU_IP}:{RSU_PORT}，發送頻率: {frequency}s ---")
    try:
        while True:
            packet = gen_packet(obu_id, check_RSU())
            send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))
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