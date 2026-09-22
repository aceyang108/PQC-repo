import time, random, json

def generate_ssm_payload(obu_id, intersection_id=1, approach_id=1, request_id=1, status=4):
    """
    產生符合 SAE J2735 SEP2024 (Section 5.28) 的精簡號誌狀態訊息 (Signal Status Message, SSM, msgID=30)
    作為路口 RSU 回應緊急車輛 SRM 優先號誌請求之回條 (ACK)。
    只保留必要欄位 (Mandatory)，嚴格剔除所有非必要之 Optional 欄位以實現極簡傳輸負載 (~240 bytes)。
    
    參數:
      - obu_id: 請求車輛識別碼 (例如: "AMB-217")
      - intersection_id: 目標路口編號 (預設: 1)
      - approach_id: 進口道編號 (預設: 1)
      - request_id: 請求識別流水號 (預設: 1)
      - status: 優先權回應狀態 (4 = granted 放行/核准, 5 = rejected 拒絕)
    """
    now = time.time()
    dsecond = int((now % 60) * 1000)

    ssm_data = {
        "msgID": 30,             # SAE J2735 DE_DSRC_MessageID: signalStatusMessage = 30
        "second": dsecond,       # DE_DSecond (0..65535 ms)
        "sequenceNumber": random.randint(0, 127), # DE_MsgCount (0..127)
        "status": [              # DF_SignalStatusList
            {
                "sequenceNumber": 1,
                "id": {"id": intersection_id}, # DF_IntersectionReferenceID (省略可選 region)
                "sigStatus": [    # DF_SignalStatusPackageList
                    {
                        "requester": {  # DF_SignalRequesterInfo
                            "id": {"entityID": obu_id}, # DF_VehicleID
                            "request": request_id,      # DE_RequestID
                            "sequenceNumber": 1,        # DE_MsgCount
                            "role": 14                  # DE_BasicVehicleRole: 14=ambulance
                        },
                        "inboundOn": {"approach": approach_id}, # DF_IntersectionAccessPoint
                        "status": status                # DE_PrioritizationResponseStatus: 4=granted
                    }
                ]
            }
        ],
        "full_timestamp": now
    }
    return ssm_data
