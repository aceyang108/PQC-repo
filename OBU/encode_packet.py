import struct
import json
from OBU.signature_oqs import master_sign

def gen_packet(obu_id, known_RSU=False):
    # Delegate to master_sign which respects the active mode (Pure Python, JIT, or liboqs)
    packet, msg_len, cert_len, sig_len = master_sign(obu_id, known_RSU)
    
    print("\033[1;36m┌────────────────────────────────────────────────────────┐\033[0m")
    print("\033[1;36m│            [OBU 封包包裝器 - 混合簽章安全傳輸]          │\033[0m")
    print("\033[1;36m├────────────────────────────────────────────────────────┤\033[0m")
    print(f"\033[1;33m│ 消息 Payload 長度:\033[0m {msg_len:<4} 位元組 (bytes){:<19} \033[1;36m│\033[0m")
    print(f"\033[1;33m│ 隱式憑證長度     :\033[0m {cert_len:<4} 位元組 (bytes) [{'短憑證 (省85.5%)' if cert_len==49 else '完整註冊憑證':<14}] \033[1;36m│\033[0m")
    print(f"\033[1;33m│ H-FSwA 簽章長度  :\033[0m {sig_len:<4} 位元組 (bytes) (選定後量子核心) \033[1;36m│\033[0m")
    print(f"\033[1;33m│ 封包總體積大小   :\033[0m {len(packet):<4} 位元組 (bytes){:<19} \033[1;36m│\033[0m")
    print("\033[1;36m├────────────────────────────────────────────────────────┤\033[0m")
    print("\033[1;36m│ \033[1;32m【傳輸發送】 ───> 📡 廣播安全 BSM 封包中...            \033[1;36m│\033[0m")
    print("\033[1;36m└────────────────────────────────────────────────────────┘\033[0m\n")

    return packet