# SPDX-License-Identifier: GPL-3.0-or-later
"""09_syn_dup.pcap: SYN 重複・RST 後・seq 穴の埋め戻しの再送判定分離用

目的: 再送判定の候補(A4/A5/B/C/C5)で割り切れない SYN 重複条件と
seq 穴の埋め戻しの扱いを nProbe 10.4 の観測で確定する
シナリオ S1〜S10(各シナリオ = 独立 5-tuple)
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.9.1"
S_IP = "198.18.9.2"
DST_PORT = 80

WIN = 8192

# IP 全長(20+20+payload)を分かりやすくするペイロード
P100 = b"\x41" * 100
P50 = b"\x42" * 50
P4 = b"\x43" * 4
P1 = b"\x44" * 1


def handshake(packets: List[Packet], sport: int, c_seq: int, s_seq: int, t: int) -> None:
    """3-way ハンドシェイク(SYN / SYN-ACK / ACK)を追加する"""
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq, ack=0, flags="S",
                           win=WIN, time_=at(t)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, sport, seq=s_seq, ack=c_seq + 1, flags="SA",
                           win=WIN, time_=at(t, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq + 1, ack=s_seq + 1, flags="A",
                           win=WIN, time_=at(t, 20000)))


def main() -> None:
    packets: List[Packet] = []

    # S1 (sport 41001, t=0): RST 応答後の再 SYN
    # 相手(RST-ACK)応答後の SYN 重複 -> A5 では数えない、nProbe が数えるなら A5 は誤り
    handshake(packets, 41001, 1000, 5000, 0)
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41001, seq=5000, ack=1001, flags="RA",
                           win=WIN, time_=at(0, 50000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41001, DST_PORT, seq=1000, ack=0, flags="S",
                           win=WIN, time_=at(1)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41001, seq=5000, ack=1001, flags="SA",
                           win=WIN, time_=at(1, 100000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41001, DST_PORT, seq=1001, ack=5001, flags="A",
                           win=WIN, time_=at(1, 200000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41001, DST_PORT, seq=1001, ack=5001, flags="FA",
                           win=WIN, time_=at(1, 300000)))

    # S2 (sport 41002, t=10): SYN-ACK の重複(数えない想定)
    handshake(packets, 41002, 2000, 5100, 10)
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41002, seq=5100, ack=2001, flags="SA",
                           win=WIN, time_=at(10, 100000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41002, DST_PORT, seq=2001, ack=5101, flags="PA",
                           payload=P100, win=WIN, time_=at(10, 200000)))

    # S3 (sport 41003, t=20): SYN-ACK 後 9 秒の再 SYN(数えない想定)
    handshake(packets, 41003, 3000, 5200, 20)
    packets.append(tcp_pkt(C_IP, S_IP, 41003, DST_PORT, seq=3000, ack=0, flags="S",
                           win=WIN, time_=at(29)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41003, seq=5200, ack=3001, flags="SA",
                           win=WIN, time_=at(29, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41003, DST_PORT, seq=3001, ack=5201, flags="PA",
                           payload=P100, win=WIN, time_=at(29, 100000)))

    # S4 (sport 41004, t=40): SYN だけ 3 回(相手応答前の自発的 SYN 再送 -> 数える想定)
    packets.append(tcp_pkt(C_IP, S_IP, 41004, DST_PORT, seq=4000, ack=0, flags="S",
                           win=WIN, time_=at(40)))
    packets.append(tcp_pkt(C_IP, S_IP, 41004, DST_PORT, seq=4000, ack=0, flags="S",
                           win=WIN, time_=at(40, 500000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41004, DST_PORT, seq=4000, ack=0, flags="S",
                           win=WIN, time_=at(41)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41004, seq=5300, ack=4001, flags="SA",
                           win=WIN, time_=at(41, 500000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41004, DST_PORT, seq=4001, ack=5301, flags="A",
                           win=WIN, time_=at(41, 600000)))

    # S5 (sport 41005, t=50): 純 ACK の seq で穴が示された後の埋め戻し(数える想定)
    # 純ACK seq=5001 の後、seq=5005 からデータ -> 5001〜5005 に穴。seq=5001 len=4 で埋め戻し
    handshake(packets, 41005, 5000, 5400, 50)
    packets.append(tcp_pkt(C_IP, S_IP, 41005, DST_PORT, seq=5001, ack=5401, flags="A",
                           win=WIN, time_=at(50, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41005, DST_PORT, seq=5005, ack=5401, flags="PA",
                           payload=P100, win=WIN, time_=at(50, 300000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41005, DST_PORT, seq=5001, ack=5401, flags="PA",
                           payload=P4, win=WIN, time_=at(50, 500000)))

    # S6 (sport 41006, t=60): データパケットで示された穴の埋め戻し(C: 数えない想定)
    # データ1 seq=6001 len=4 (hi=6005) -> データ2 seq=6009 len=4 (hi=6013、穴 6005〜6009)
    # -> データ3 seq=6005 len=4(埋め戻し)。A4 では数える、C では数えない
    handshake(packets, 41006, 6000, 5500, 60)
    packets.append(tcp_pkt(C_IP, S_IP, 41006, DST_PORT, seq=6001, ack=5501, flags="PA",
                           payload=P4, win=WIN, time_=at(60, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41006, DST_PORT, seq=6009, ack=5501, flags="PA",
                           payload=P4, win=WIN, time_=at(60, 300000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41006, DST_PORT, seq=6005, ack=5501, flags="PA",
                           payload=P4, win=WIN, time_=at(60, 500000)))

    # S7 (sport 41007, t=70): FIN の重複(数えない想定)
    handshake(packets, 41007, 7000, 5600, 70)
    packets.append(tcp_pkt(C_IP, S_IP, 41007, DST_PORT, seq=7001, ack=5601, flags="PA",
                           payload=P50, win=WIN, time_=at(70, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41007, DST_PORT, seq=7051, ack=5601, flags="FA",
                           win=WIN, time_=at(70, 200000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41007, DST_PORT, seq=7051, ack=5601, flags="FA",
                           win=WIN, time_=at(70, 300000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41007, seq=5601, ack=7052, flags="FA",
                           win=WIN, time_=at(70, 400000), c2s=False))

    # S8 (sport 41008, t=80): キープアライブ 1 バイト(seq=hi-1 -> 数える想定)
    handshake(packets, 41008, 8000, 5700, 80)
    packets.append(tcp_pkt(C_IP, S_IP, 41008, DST_PORT, seq=8001, ack=5701, flags="PA",
                           payload=P100, win=WIN, time_=at(80, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 41008, DST_PORT, seq=8100, ack=5701, flags="PA",
                           payload=P1, win=WIN, time_=at(110)))

    # S9 (sport 41009, t=120): RST 後 5 秒のデータ再送(22 秒以内 -> 数える想定)
    handshake(packets, 41009, 9000, 5800, 120)
    packets.append(tcp_pkt(C_IP, S_IP, 41009, DST_PORT, seq=9001, ack=5801, flags="PA",
                           payload=P100, win=WIN, time_=at(120, 100000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41009, seq=5801, ack=9101, flags="RA",
                           win=WIN, time_=at(120, 200000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41009, DST_PORT, seq=9001, ack=5801, flags="PA",
                           payload=P100, win=WIN, time_=at(125)))

    # S10 (sport 41010, t=140): RST 後 40 秒のデータ再送(22 秒超 -> 数えない/新フロー想定)
    handshake(packets, 41010, 10000, 5900, 140)
    packets.append(tcp_pkt(C_IP, S_IP, 41010, DST_PORT, seq=10001, ack=5901, flags="PA",
                           payload=P100, win=WIN, time_=at(140, 100000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 41010, seq=5901, ack=10101, flags="RA",
                           win=WIN, time_=at(140, 200000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 41010, DST_PORT, seq=10001, ack=5901, flags="PA",
                           payload=P100, win=WIN, time_=at(180)))

    write("09_syn_dup.pcap", packets)
    print("09_syn_dup.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
