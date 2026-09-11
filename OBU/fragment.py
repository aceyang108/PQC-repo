import struct, time, hashlib

MAX_PAYLOAD = 1400

def make_fragments(packet: bytes, msg_id: int = 1):
    """
    實作分片雜湊承諾 (Fragment Hash Commitment) 切片與封包組裝：
    1. 採用 V2X 最佳化動態切片，嚴格保證單一 UDP 封包 <= 1472 Bytes (低於 MTU 1500，零 IP 碎片)
    2. 消除只有十幾 bytes 的冗餘第 4 片：4.2KB Full 封包精準切為 3 片，2.9KB Short 封包切為 2 片
    3. 計算後續分片之 SHA-256 雜湊承諾並注入 F1
    """
    total_len = len(packet)

    if total_len <= 1400:
        total_frags = 1
    elif total_len <= 2903:
        total_frags = 2
    elif total_len <= 4300:
        total_frags = 3
    else:
        total_frags = (total_len + 1400) // 1400

    raw_chunks = []
    if total_frags == 1:
        raw_chunks = [packet]
    else:
        # F1 需預留雜湊承諾空間 (1 + (total_frags - 1) * 32)
        if total_frags == 2:
            f1_size = min(1435, total_len // 2)
        elif total_frags == 3:
            f1_size = min(1380, total_len // 3)
        else:
            f1_size = min(1350, total_len // total_frags)

        raw_chunks.append(packet[:f1_size])

        remaining = packet[f1_size:]
        other_frags = total_frags - 1
        chunk_size = (len(remaining) + other_frags - 1) // other_frags
        for i in range(other_frags):
            start = i * chunk_size
            end = min(start + chunk_size, len(remaining))
            if start < len(remaining):
                raw_chunks.append(remaining[start:end])

    # 1. 計算後續分片 (F2, F3...) 的 SHA-256 雜湊清單
    # 格式：num_hashes (1B) | H_2 (32B) | H_3 (32B)...
    tail_hashes = b""
    if total_frags > 1:
        tail_hashes += struct.pack('!B', total_frags - 1)
        for chunk in raw_chunks[1:]:
            tail_hashes += hashlib.sha256(chunk).digest()
    else:
        tail_hashes += struct.pack('!B', 0)

    # 將雜湊承諾前綴注入 F1 內容的開頭 (約 33~65 bytes，遠低於 MTU)
    f1_chunk_with_commitment = tail_hashes + raw_chunks[0]

    packets = []
    for i in range(total_frags):
        seq_num = i + 1
        chunk = f1_chunk_with_commitment if seq_num == 1 else raw_chunks[i]

        # Header (4 bytes)：目前序號(1) | 總分片數(1) | 訊息ID(2)
        app_header = struct.pack('!BBH', seq_num, total_frags, msg_id)
        packets.append(app_header + chunk)

    return packets

def send_fragment(sock, msg_id, packet, dst: tuple):
    """
    依照分片雜湊承諾發送分片，並在最後發送備用 F1 提升抗丟包率
    """
    packets = make_fragments(packet, msg_id)
    total_frags = len(packets)

    for i, udp_packet in enumerate(packets):
        seq_num = i + 1
        sock.sendto(udp_packet, dst)
        print(f"發送碎片 {seq_num}/{total_frags}, 大小: {len(udp_packet)} bytes (含防注入承諾標頭)")

    # 3. 尾端多發一次 F1 備用包 (時間分集防掉包)
    if len(packets) > 0:
        sock.sendto(packets[0], dst)
        print(f"發送碎片 1/{total_frags} [備用], 大小: {len(packets[0])} bytes")

    print()