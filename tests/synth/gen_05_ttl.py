# SPDX-License-Identifier: GPL-3.0-or-later
"""05_ttl.pcap: TTL 違いを混ぜた TCP フロー群

目的: MIN/MAX_TTL が「S2D のパケットのうちフロー最初のパケットを除いたもの」の
TTL かを検証する。SYN(最初のパケット)と SYN-ACK(D2S)に極端な TTL を入れて
それらが出力に現れないことを確認する
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.6.1"
S_IP = "198.18.6.2"
DST_PORT = 80


def main() -> None:
    packets: List[Packet] = []

    # T1: SYN に TTL=1(最初のパケット・除外対象)、SYN-ACK に TTL=7(D2S・無視対象)、
    #     ACK=64 / データ=255 → 期待 MIN=64 / MAX=255
    packets.append(tcp_pkt(C_IP, S_IP, 40021, DST_PORT, seq=1000, ack=0, flags="S",
                           ttl=1, time_=at(0)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40021, seq=5000, ack=1001, flags="SA",
                           ttl=7, time_=at(0, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 40021, DST_PORT, seq=1001, ack=5001, flags="A",
                           ttl=64, time_=at(0, 20000)))
    packets.append(tcp_pkt(C_IP, S_IP, 40021, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=b"\x41" * 100, ttl=255, time_=at(0, 30000)))

    # T2: SYN のみ(S2D の 2 個目以降なし)→ 期待 MIN=MAX=0(該当なし)
    packets.append(tcp_pkt(C_IP, S_IP, 40022, DST_PORT, seq=2000, ack=0, flags="S",
                           ttl=100, time_=at(1)))

    # T3: SYN に TTL=32(除外対象)、ACK=64 / データ=128 → 期待 MIN=64 / MAX=128
    packets.append(tcp_pkt(C_IP, S_IP, 40023, DST_PORT, seq=3000, ack=0, flags="S",
                           ttl=32, time_=at(2)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40023, seq=5000, ack=3001, flags="SA",
                           ttl=7, time_=at(2, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 40023, DST_PORT, seq=3001, ack=5001, flags="A",
                           ttl=64, time_=at(2, 20000)))
    packets.append(tcp_pkt(C_IP, S_IP, 40023, DST_PORT, seq=3001, ack=5001, flags="PA",
                           payload=b"\x42" * 100, ttl=128, time_=at(2, 30000)))

    write("05_ttl.pcap", packets)
    print("05_ttl.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
