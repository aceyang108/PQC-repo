import socket, time
import RSU.parse as parse

# 配置參數
RSU_IP = "0.0.0.0"  # 監聽所有可用的網路介面
RSU_PORT = 5005     # 自定義連接埠
BUFFER_SIZE = 4096  # 預留稍大緩衝區，為之後的 PQC 簽章做準備

# 要改成用 (msg_id, addr) 當 key，這樣就不會有不同車輛的訊息混在一起了
reassemble_buffer = {}  # 用於存儲分片資料的緩衝區，key 為 (msg_id, addr)，value 為分片列表

def receive_data(sock):
    try:
        while True:
            # 接收資料
            # data: 接收到的位元組資料
            # addr: 發送端的 (IP, Port)
            data, addr = sock.recvfrom(BUFFER_SIZE)

            header_bytes = data[:4]  # 前 4 個位元組是 header
            chunk_bytes = data[4:]  # 剩下的位元組是封包本身內容

            # Header (4 bytes)：目前分片序列號(1) | 總分片數(1) | 訊息ID(2)
            seq_num, total_frags, msg_id = parse.parse_header(header_bytes)
            if seq_num is None:
                print(f"[來自 {addr}] 收到無效的 header，忽略此訊息")
                continue

            if (msg_id, addr) not in reassemble_buffer:
                reassemble_buffer[(msg_id, addr)] = [None] * total_frags  # 初始化分片列表

            print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})。")

            # 將分片存入緩衝區
            reassemble_buffer[(msg_id, addr)][seq_num-1] = chunk_bytes

            # 檢查是否所有分片都已收到
            if all(fragment is not None for fragment in reassemble_buffer[(msg_id, addr)]):
                print(f"[來自 {addr}] 已收到ID為 {msg_id} 的所有分片。")
                # 重組訊息
                packet = b''.join(reassemble_buffer[(msg_id, addr)])  # 將分片列表中的位元組串接成完整封包
                # 清除緩衝區
                del reassemble_buffer[(msg_id, addr)]

                payload = parse.parse_packet(packet)  # 將重組後的訊息轉回位元組並解析

                if payload:
                    latency = time.time() - payload['full_timestamp']
                    print("\033[1;32m┌────────────────────────────────────────────────────────┐\033[0m")
                    print("\033[1;32m│            [RSU 驗證成功 - 安全優先通行准許]             │\033[0m")
                    print("\033[1;32m├────────────────────────────────────────────────────────┤\033[0m")
                    print(f"\033[1;36m│ 來源車輛 ID  :\033[0m {payload.get('obu_id', 'Unknown'):<37} \033[1;32m│\033[0m")
                    print(f"\033[1;36m│ 消息序號 ID  :\033[0m {payload.get('msgID', 0):<37} \033[1;32m│\033[0m")
                    print(f"\033[1;36m│ 傳輸暨驗簽延遲:\033[0m {latency*1000:.2f} 毫秒 (ms){:<21} \033[1;32m│\033[0m")
                    print("\033[1;32m├────────────────────────────────────────────────────────┤\033[0m")
                    print("\033[1;32m│ \033[1;33m核心安全數據 (BSM Core Data):\033[0m                          \033[1;32m│\033[0m")
                    core = payload.get('coreData', {})
                    print(f"\033[1;32m│\033[0m   - 緯度 (Lat): {core.get('latitude', 0.0):<38} \033[1;32m│\033[0m")
                    print(f"\033[1;32m│\033[0m   - 經度 (Lon): {core.get('longitude', 0.0):<38} \033[1;32m│\033[0m")
                    print(f"\033[1;32m│\033[0m   - 車速 (Spd): {core.get('speed', 0.0):<5} km/h{:<28} \033[1;32m│\033[0m")
                    print(f"\033[1;32m│\033[0m   - 航向 (Hdg): {core.get('heading', 0.0):<5} deg{:<29} \033[1;32m│\033[0m")
                    print("\033[1;32m├────────────────────────────────────────────────────────┤\033[0m")
                    print("\033[1;32m│ \033[1;35m【緊急控制動作】 ───> 🔴 號誌切換為 [緊急綠燈]!!! 🟢\033[0m   \033[1;32m│\033[0m")
                    print("\033[1;32m└────────────────────────────────────────────────────────┘\033[0m\n")
                else:
                    print("\033[1;31m┌────────────────────────────────────────────────────────┐\033[0m")
                    print("\033[1;31m│            [RSU 驗證失敗 - 安全威脅拒絕通行]             │\033[0m")
                    print("\033[1;31m├────────────────────────────────────────────────────────┤\033[0m")
                    print(f"\033[1;31m│ 來源 IP 位址 :\033[0m {addr[0]:<37} \033[1;31m│\033[0m")
                    print("\033[1;31m├────────────────────────────────────────────────────────┤\033[0m")
                    print("\033[1;31m│ \033[1;33m【警報警告】 ───> ❌ 封包簽章偽造或憑證過期，拒絕通行！\033[0m \033[1;31m│\033[0m")
                    print("\033[1;31m└────────────────────────────────────────────────────────┘\033[0m\n")
    except KeyboardInterrupt:
        print("\n\033[1;31mRSU 已手動關閉\033[0m")
    finally:
        sock.close()
 
if __name__ == "__main__":
    # 建立 UDP Socket
    # socket.AF_INET 代表使用 IPv4
    # socket.SOCK_DGRAM 代表使用 UDP 協議
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 
    # 將 Socket 綁定到 IP 與 Port
    sock.bind((RSU_IP, RSU_PORT))
    print(f"\033[1;36m--- RSU 已啟動，正在監聽連接埠 {RSU_PORT} (後量子防禦模式開啟) ---\033[0m")
    receive_data(sock)