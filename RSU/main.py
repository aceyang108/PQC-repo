import socket, time, os
import RSU.parse as parse

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

# 核心配置參數
RSU_IP = os.getenv("RSU_LISTEN_IP", "0.0.0.0") 
RSU_PORT = int(os.getenv("RSU_PORT", 5005))
BUFFER_SIZE = 4096
PRUNING_TIMEOUT = 0.08 # 80 毫秒（配合 150ms 端到端延遲）
SOCKET_TIMEOUT = 0.01   # 10 毫秒輪詢週期，Non-blocking

# 重組緩衝區，key= (msg_id, addr)
# value 為 session dict: {"state": ..., "start_time": ..., "total_frags": ..., "fragments": [...], "created_at": ...}
reassemble_buffer = {}

# 最近已完成重組的 (msg_id, addr)，避免尾巴重複分片再次觸發新 session
recent_completed = {}

# 定時檢查
def prune_expired_sessions():
    now = time.time()
    # 清理超過 2 秒的已完成紀錄
    for key, done_time in list(recent_completed.items()):
        if now - done_time > 2.0:
            del recent_completed[key]

    pruned_keys = []
    for key, session in list(reassemble_buffer.items()):
        # 若 F1 已抵達，以 F1 抵達時間倒數 80ms
        if session["start_time"] is not None:
            elapsed = now - session["start_time"]
            if elapsed > PRUNING_TIMEOUT:
                pruned_keys.append((key, elapsed))
        # 沒收到F1，超過 1 秒同樣清空
        elif now - session["created_at"] > 1.0:
            pruned_keys.append((key, 1.0))

    for key, elapsed in pruned_keys:
        msg_id, addr = key
        print(f"\n[超時清理] 訊息 ID={msg_id} [來自 {addr}] 逾時 ({elapsed*1000:.1f}ms > {PRUNING_TIMEOUT*1000:.0f}ms) 碎片不齊")
        print(f"清空快取，號誌維持正常週期\n")
        del reassemble_buffer[key]

# 處理收到的分片
def process_fragment(data, addr):
    header_bytes = data[:4]
    chunk_bytes = data[4:]
    seq_num, total_frags, msg_id = parse.parse_header(header_bytes) # Header (4 bytes)：序號(1) | 總分片數(1) | 訊息ID(2)
    if seq_num is None:
        print(f"[來自 {addr}] 收到無效的 header")
        return

    session_key = (msg_id, addr)

    # 若該訊息剛重組完成，忽略後續抵達的重複分片 (如尾巴備用 F1)
    if session_key in recent_completed:
        return

    # 初始化
    if session_key not in reassemble_buffer:
        reassemble_buffer[session_key] = {
            "state": "WAITING_F1",
            "start_time": None,
            "total_frags": total_frags,
            "fragments": [None] * total_frags,
            "created_at": time.time()
        }
    session = reassemble_buffer[session_key]

    # 收到 F1 先驗證 ECC，通過後進入閃黃燈並計時
    if seq_num == 1:
        if session["start_time"] is None:
            f1_valid, obu_id_str, _ = parse.verify_f1_ecc(chunk_bytes)
            if f1_valid:
                session["start_time"] = time.time()
                session["state"] = "REASSEMBLING"
                print(f"[來自 {addr}] 車輛 {obu_id_str} F1 ECC 驗證通過，進入預備放行 (閃黃燈)，啟動 {PRUNING_TIMEOUT*1000:.0f}ms 計時器")
            else:
                print(f"[來自 {addr}] F1 ECC 驗證失敗，拒絕閃黃燈，清除暫存")
                del reassemble_buffer[session_key]
                return
        else:
            print(f"[來自 {addr}] 收到重複 F1 備用包，自動忽略")
            return

    print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})。")
    session["fragments"][seq_num - 1] = chunk_bytes #Store

    # 檢查是否收齊
    if all(fragment is not None for fragment in session["fragments"]):
        elapsed_reassembly = time.time() - session["start_time"] if session["start_time"] else 0
        print(f"[來自 {addr}] 已收齊 ID為 {msg_id} 的所有分片 ({elapsed_reassembly*1000:.2f}ms)")
        packet = b''.join(session["fragments"])
        del reassemble_buffer[session_key]
        recent_completed[session_key] = time.time()
        # 密碼驗證
        payload = parse.parse_packet(packet)
        if payload:
            total_latency = time.time() - payload['full_timestamp']
            # 檢查延遲防重放攻擊 (150ms)
            if total_latency > 0.15:
                print(f"\n[逾期] 封包總延遲 ({total_latency*1000:.1f}ms > 150ms)，疑似重放攻擊！")
                print(f"拒絕放行，號誌維持正常週期\n")
                return

            print(f"\n[來自 {addr}] 驗證成功，切換緊急綠燈")
            print(f"[Pre-warming] 向鄰近號誌發送預熱訊號")
            print(f"端到端總耗時：{total_latency:.4f} 秒")
            print(f"\n完整訊息：")
            for key, value in payload.items():
                if key == 'coreData':
                    print(f"{key}: ", end="{\n")
                    for sub_key, sub_value in value.items():
                        print(f"  {sub_key}: {sub_value}")
                    print("}")
                else:
                    print(f"{key}: {value}")
            print()
        else:
            print(f"\n驗證失敗，拒絕通行")
            print(f"號誌維持正常週期\n")

def receive_data(sock):
    sock.settimeout(SOCKET_TIMEOUT)  # 設定 Non-blocking 輪詢超時
    try:
        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                process_fragment(data, addr)
            except socket.timeout:
                pass  # 正常超時，繼續執行
            # 檢查是否有超時分片需要清理
            prune_expired_sessions()

    except KeyboardInterrupt:
        print("\nRSU 已手動關閉")
    finally:
        sock.close()

if __name__ == "__main__":
    # (REmote CA)建立 UDP Socket 
    # socket.AF_INET 代表使用 IPv4
    # socket.SOCK_DGRAM 代表使用 UDP 協議
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 將 Socket 綁定到 IP 與 Port
    sock.bind((RSU_IP, RSU_PORT))
    print(f"RSU啟動，正在監聽 {RSU_PORT}")
    receive_data(sock)