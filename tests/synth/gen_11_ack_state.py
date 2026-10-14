"""11_ack_state.pcap: 純 ACK が再送判定の「直前 seg」状態を更新するかの判別

S15 (sport 43001, t=0): PA(1,len=10) -> 純 ACK(seq=11) -> PA(1,len=10) 再送
  - 純 ACK を状態に記録しない場合: 直前 seg は PA(1,11) -> 完全一致 -> 再送 1 (1/50)
  - 純 ACK を状態に記録する場合:   直前 seg は (11,11) -> 不一致 -> 再送 0
S16 (sport 43002, t=10): PA(1,len=10) -> 純 ACK(seq=11) -> 純 ACK(seq=11) 重複 -> PA(1,len=10)
  - 純 ACK 重複が数えられるかの確認(S5 では handshake 直後で 0 だった)
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, write

C_IP = "198.18.12.1"
S_IP = "198.18.12.2"
DST_PORT = 80
WIN = 8192
P10 = b"\x41" * 10


def handshake(packets: List[Packet], sport: int, c_seq: int, s_seq: int, t: int) -> None:
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq, ack=0, flags="S",
                           win=WIN, time_=at(t)))
    packets.append(tcp_pkt(S_IP, C_IP, DST_PORT, sport, seq=s_seq, ack=c_seq + 1, flags="SA",
                           win=WIN, time_=at(t, 10000), c2s=False))
    packets.append(tcp_pkt(C_IP, S_IP, sport, DST_PORT, seq=c_seq + 1, ack=s_seq + 1, flags="A",
                           win=WIN, time_=at(t, 20000)))


def main() -> None:
    packets: List[Packet] = []

    # S15: PA -> 純 ACK -> PA 再送(直前が純 ACK)
    handshake(packets, 43001, 1000, 5000, 0)
    packets.append(tcp_pkt(C_IP, S_IP, 43001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=P10, win=WIN, time_=at(0, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 43001, DST_PORT, seq=1011, ack=5001, flags="A",
                           win=WIN, time_=at(0, 200000)))
    packets.append(tcp_pkt(C_IP, S_IP, 43001, DST_PORT, seq=1001, ack=5001, flags="PA",
                           payload=P10, win=WIN, time_=at(0, 300000)))

    # S16: PA -> 純 ACK -> 純 ACK 重複 -> PA 再送
    handshake(packets, 43002, 2000, 5100, 10)
    packets.append(tcp_pkt(C_IP, S_IP, 43002, DST_PORT, seq=2001, ack=5101, flags="PA",
                           payload=P10, win=WIN, time_=at(10, 100000)))
    packets.append(tcp_pkt(C_IP, S_IP, 43002, DST_PORT, seq=2011, ack=5101, flags="A",
                           win=WIN, time_=at(10, 200000)))
    packets.append(tcp_pkt(C_IP, S_IP, 43002, DST_PORT, seq=2011, ack=5101, flags="A",
                           win=WIN, time_=at(10, 300000)))
    packets.append(tcp_pkt(C_IP, S_IP, 43002, DST_PORT, seq=2001, ack=5101, flags="PA",
                           payload=P10, win=WIN, time_=at(10, 400000)))

    write("11_ack_state.pcap", packets)
    print("11_ack_state.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
