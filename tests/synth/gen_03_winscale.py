# SPDX-License-Identifier: GPL-3.0-or-later
"""03_winscale.pcap: window scale option(scale=7)付きハンドシェイク + 大きな window 値

目的: TCP_WIN_MAX_IN/OUT が TCP ヘッダの 16bit window 値そのままか(scale を掛けた値か)
を検証する。scale=7 のとき 64240/65535/1024 は、掛けないならそのまま、
掛けるなら 8222720/8388480/131072 になるので区別がつく
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.4.1"
S_IP = "198.18.4.2"
DST_PORT = 443

WSCALE = [("WScale", 7)]


def main() -> None:
    packets: List[Packet] = []

    # W1: クライアント window 64240 / サーバ window 65535 + 双方向のデータ
    packets.append(tcp_pkt(C_IP, S_IP, 40010, DST_PORT, seq=1000, ack=0, flags="S",
                           win=64240, options=WSCALE, time_=at(0)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40010, seq=5000, ack=1001, flags="SA",
                           win=65535, options=WSCALE, time_=at(0, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 40010, DST_PORT, seq=1001, ack=5001, flags="A",
                           win=64240, time_=at(0, 20000)))
    packets.append(tcp_pkt(C_IP, S_IP, 40010, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=b"\x41" * 200, win=64240, time_=at(0, 30000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40010, seq=5001, ack=1101, flags="PA",
                           payload=b"\x42" * 500, win=65535, time_=at(0, 40000), c2s=False))

    # W2: クライアント window 1024(scale 掛けると 131072 で区別がつく)
    packets.append(tcp_pkt(C_IP, S_IP, 40011, DST_PORT, seq=2000, ack=0, flags="S",
                           win=1024, options=WSCALE, time_=at(1)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40011, seq=6000, ack=2001, flags="SA",
                           win=65535, options=WSCALE, time_=at(1, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 40011, DST_PORT, seq=2001, ack=6001, flags="A",
                           win=1024, time_=at(1, 20000)))
    packets.append(tcp_pkt(C_IP, S_IP, 40011, DST_PORT, seq=2001, ack=6001, flags="PA",
                           payload=b"\x43" * 100, win=1024, time_=at(1, 30000)))

    write("03_winscale.pcap", packets)
    print("03_winscale.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
