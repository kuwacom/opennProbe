"""10_syn_extra.pcap: E3 vs E4 の判別 + RST/FIN 後の idle 期限挙動

目的:
- S11: PA -> キープアライブ(部分被覆) -> PA再送。E3 なら 0 / E4・C5 なら 1
- S12: PA -> 前進 PA -> 2個前の PA 再送。E3/E4 なら 0 / C5(被覆)なら 1
- S13: データ -> RST -> 61.3 秒後の再送。idle timeout(60s)でフロー分割されるか
- S14: データ -> FIN/FIN-ACK -> 61.2 秒後の FIN 再送。同上

仕様: helper.py(gen_XX 共通)。時刻は時刻順に配置する
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.11.1"
S_IP = "198.18.11.2"
DST_PORT = 80
WIN = 8192

P100 = b"\x41" * 100
P50 = b"\x42" * 50


def handshake(packets: List[Packet], sport: int, c_seq: int, s_seq: int, t: int) -> None:
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq, ack=0, flags="S",
                           win=WIN, time_=at(t)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, sport, seq=s_seq, ack=c_seq + 1, flags="SA",
                           win=WIN, time_=at(t, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq + 1, ack=s_seq + 1, flags="A",
                           win=WIN, time_=at(t, 20000)))


def main() -> None:
    packets: List[Packet] = []

    # S11 (sport 42001, t=0): PA(1,100) -> KA PA(91,1) -> PA(1,100) 再送
    # E3: 直前 KA (91,92) と不一致 -> 0 / E4: hi4=101 の setter seq=1 と一致 -> 1
    handshake(packets, 42001, 1000, 5000, 0)
    packets.append(tcp_pkt(C_IP, S_IP, 42001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=P100, win=WIN, time_=at(0, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42001, DST_PORT, seq=1091, ack=5001, flags="PA",
                           payload=b"\x44" * 1, win=WIN, time_=at(0, 300000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=P100, win=WIN, time_=at(0, 500000)))

    # S12 (sport 42002, t=10): PA(1,100) -> PA(101,50) -> PA(1,100) 再送(2個前と一致)
    # E3: 直前 (101,151) と不一致 -> 0 / E4: hi4=151 の setter=101 -> 0 / C5: 被覆 -> 1
    handshake(packets, 42002, 2000, 5100, 10)
    packets.append(tcp_pkt(C_IP, S_IP, 42002, DST_PORT, seq=2001, ack=5101, flags="PA",
                           payload=P100, win=WIN, time_=at(10, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42002, DST_PORT, seq=2101, ack=5101, flags="PA",
                           payload=P50, win=WIN, time_=at(10, 300000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42002, DST_PORT, seq=2001, ack=5101, flags="PA",
                           payload=P100, win=WIN, time_=at(10, 500000)))

    # S13 (sport 42003, t=20): データ -> RST -> 61.3 秒後の再送(idle timeout 60s 超え)
    # 分割されれば idle は RST 後も通常動作(22 秒仮説の特別扱いは無い)
    handshake(packets, 42003, 3000, 5200, 20)
    packets.append(tcp_pkt(C_IP, S_IP, 42003, DST_PORT, seq=3001, ack=5201, flags="PA",
                           payload=P100, win=WIN, time_=at(20, 100000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 42003, seq=5201, ack=3101, flags="RA",
                           win=WIN, time_=at(20, 200000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 42003, DST_PORT, seq=3001, ack=5201, flags="PA",
                           payload=P100, win=WIN, time_=at(81, 500000)))

    # S14 (sport 42004, t=100): データ -> FIN/FIN-ACK -> 61.2 秒後の FIN 再送
    handshake(packets, 42004, 4000, 5300, 100)
    packets.append(tcp_pkt(C_IP, S_IP, 42004, DST_PORT, seq=4001, ack=5301, flags="PA",
                           payload=P50, win=WIN, time_=at(100, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42004, DST_PORT, seq=4051, ack=5301, flags="FA",
                           win=WIN, time_=at(100, 200000)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, 42004, seq=5301, ack=4052, flags="FA",
                           win=WIN, time_=at(100, 300000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, 42004, DST_PORT, seq=4052, ack=5302, flags="A",
                           win=WIN, time_=at(100, 400000)))
    packets.append(tcp_pkt(C_IP, S_IP, 42004, DST_PORT, seq=4052, ack=5302, flags="FA",
                           win=WIN, time_=at(161, 500000)))

    write("10_syn_extra.pcap", packets)
    print("10_syn_extra.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
