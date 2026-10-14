"""02_retrans.pcap: 同一 seq の再送を含む TCP フロー群

目的: 再送判定と RETRANSMITTED_*_BYTES(バイトは IP 全長の合計)を検証する
判定は推定規則「向き別に end = seq + payload 長 + (SYN なら 1) の最大 hi を持ち、
payload 長 + SYN > 0 かつ end <= hi なら再送」に合わせた構成とする
(SYN 重複・FIN 再送など未解明条件を含む構成は避ける)
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.3.1"
S_IP = "198.18.3.2"
DST_PORT = 80

# IP 全長 140 / 90 になるペイロード(20+20+payload)
PAYLOAD_100 = b"\x41" * 100
PAYLOAD_50 = b"\x42" * 50

WIN = 8192


def add_handshake(packets: List[Packet], sport: int, c_seq: int, s_seq: int, t: int) -> None:
    """3-way ハンドシェイク(SYN / SYN-ACK / ACK)を追加する"""
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq, ack=0, flags="S",
                           win=WIN, time_=at(t)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, sport, seq=s_seq, ack=c_seq + 1, flags="SA",
                           win=WIN, time_=at(t, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq + 1, ack=s_seq + 1, flags="A",
                           win=WIN, time_=at(t, 20000)))


def main() -> None:
    packets: List[Packet] = []

    # R1: クライアント -> サーバ方向の再送 1 回(seq=1001・IP 全長 140)
    add_handshake(packets, 40001, 1000, 5000, 0)
    packets.append(tcp_pkt(C_IP, S_IP, 40001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=PAYLOAD_100, win=WIN, time_=at(0, 30000)))
    packets.append(tcp_pkt(C_IP, S_IP, 40001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=PAYLOAD_100, win=WIN, time_=at(0, 40000)))

    # R2: 同じデータ(seq=2001)を再送 2 回 → 再送パケット 2 個を数えられる
    add_handshake(packets, 40002, 2000, 6000, 1)
    for i in range(3):
        packets.append(tcp_pkt(C_IP, S_IP, 40002, DST_PORT, seq=2001, ack=6001, flags="PA",
                               payload=PAYLOAD_100, win=WIN, time_=at(1, 30000 + 10000 * i)))

    # R3: サーバ -> クライアント方向の再送 1 回(OUT 側の再送検証用・seq=7001・IP 全長 90)
    add_handshake(packets, 40003, 3000, 7000, 2)
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40003, seq=7001, ack=3001, flags="PA",
                           payload=PAYLOAD_50, win=WIN, time_=at(2, 30000), c2s=False))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 40003, seq=7001, ack=3001, flags="PA",
                           payload=PAYLOAD_50, win=WIN, time_=at(2, 40000), c2s=False))

    write("02_retrans.pcap", packets)
    print("02_retrans.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
