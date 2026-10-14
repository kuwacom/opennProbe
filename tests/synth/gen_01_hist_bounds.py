"""01_hist_bounds.pcap: IP total length が境界を跨ぐ UDP 単発フロー群

目的: NUM_PKTS_* ヒストグラム5区間の境界(128/256/512/1024/1514 が「未満」か「以下」か)
と、1514 超(ジャンボ)が数えられるかを、1 フロー = 1 パケットで分離して検証する
ペイロード長 = 目標 IP 全長 - 20(IP) - 8(UDP) として scapy の自動計算に任せる
"""
from typing import List

from scapy.packet import Packet

from helper import at, udp_pkt, write

# 境界の両側 + ジャンボ(IP 全長 2000)。1514 ちょうどは公式実例なしの検証ポイント
TARGET_IP_LENS = [128, 129, 255, 256, 511, 512, 1023, 1024, 1513, 1514, 2000]

SRC_IP = "198.18.1.1"
DST_IP = "198.18.2.1"
DST_PORT = 9999


def main() -> None:
    packets: List[Packet] = []
    for i, ip_len in enumerate(TARGET_IP_LENS):
        # sport を変えて 1 パケットごとに独立フローにする(区間ごとに列が分離する)
        packets.append(udp_pkt(SRC_IP, DST_IP, 30001 + i, DST_PORT, ip_len=ip_len, time_=at(i)))
    write("01_hist_bounds.pcap", packets)
    print("01_hist_bounds.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
