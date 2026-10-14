# SPDX-License-Identifier: GPL-3.0-or-later
"""04_unidir.pcap: 片方向 UDP フローと双方向 UDP フロー

目的: 向き規則(src = フロー最初のパケットの送信側)と、片方向フローでの
MIN_IP_PKT_LEN = 0(dst->src パケット 0 個)の再現を検証する
返信パケットの TTL を 7 にして、TTL 列が S2D 専用か(7 が MIN_TTL に出ないか)も確認する
"""
from typing import List

from scapy.packet import Packet

from helper import at, udp_pkt, write

CLIENT1 = "198.18.5.1"
CLIENT3 = "198.18.5.3"
PEER = "198.18.5.2"
PEER_PORT = 9998


def main() -> None:
    packets: List[Packet] = []

    # U1: 片方向(クライアント -> サーバのみ・IP 全長 100/150/200)→ MIN_IP_PKT_LEN=0 を再現
    packets.append(udp_pkt(CLIENT1, PEER, 50001, PEER_PORT, ip_len=100, time_=at(0)))
    packets.append(udp_pkt(CLIENT1, PEER, 50001, PEER_PORT, ip_len=150, time_=at(0, 500000)))
    packets.append(udp_pkt(CLIENT1, PEER, 50001, PEER_PORT, ip_len=200, time_=at(1)))

    # U2: 双方向(S2D が 100/120・D2S が 80/60。MIN/MAX が両向き込みで取れるか)
    packets.append(udp_pkt(CLIENT1, PEER, 50002, PEER_PORT, ip_len=100, time_=at(2)))
    packets.append(udp_pkt(PEER, CLIENT1, PEER_PORT, 50002, ip_len=80, ttl=7,
                           time_=at(2, 100000), c2s=False))
    packets.append(udp_pkt(CLIENT1, PEER, 50002, PEER_PORT, ip_len=120, time_=at(2, 200000)))
    packets.append(udp_pkt(PEER, CLIENT1, PEER_PORT, 50002, ip_len=60, ttl=7,
                           time_=at(2, 300000), c2s=False))

    # U3: 双方向(クライアント発 200B -> サーバ発 300B。src がクライアントになるか)
    packets.append(udp_pkt(CLIENT3, PEER, 50003, PEER_PORT, ip_len=200, time_=at(4)))
    packets.append(udp_pkt(PEER, CLIENT3, PEER_PORT, 50003, ip_len=300,
                           time_=at(4, 500000), c2s=False))

    write("04_unidir.pcap", packets)
    print("04_unidir.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
