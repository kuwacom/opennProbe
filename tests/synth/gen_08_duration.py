"""08_duration.pcap: 継続時間 0・IAT 統計・lifetime timeout(120 秒)の分割

目的:
- 1 パケットの UDP フローで FLOW_DURATION_MILLISECONDS の生値 0(公式後処理で 1)を再現
- 10ms 間隔の均一/非均一 UDP フローで方向別 IAT 統計を数えられる構成を作る
- 130 秒にわたる TCP フローで lifetime timeout による分割を再現する
"""
from typing import List

from scapy.packet import Packet

from helper import at, tcp_pkt, udp_pkt, write

CLIENT = "198.18.9.1"
SERVER = "198.18.9.2"

# IP 全長 100 の UDP ペイロード
PAYLOAD_72 = b"\x00" * 72

WIN = 8192


def main() -> None:
    packets: List[Packet] = []

    # d1: 単一パケット UDP フロー(継続時間 0 → 公式後処理で 1 になる)
    packets.append(udp_pkt(CLIENT, SERVER, 50020, 9997, ip_len=100, time_=at(0)))

    # d2: 10ms 均一間隔 × 5 パケット(IAT が全部 10ms になる)
    for i in range(5):
        packets.append(udp_pkt("198.18.9.3", "198.18.9.4", 50021, 9996, ip_len=100,
                               time_=at(1, 10000 * i)))

    # d3: 間隔 10/20/30/40ms の非均一フロー(IAT_STDDEV=trunc(sqrt(125))=11 の検証用)
    for i, usec in enumerate([0, 10000, 30000, 60000, 100000]):
        packets.append(udp_pkt("198.18.9.5", "198.18.9.6", 50022, 9995, ip_len=100,
                               time_=at(2, usec)))

    # T: 130 秒にわたる TCP フロー(t=3 のハンドシェイク+データ、t=133 に同一向きのデータ)
    #    lifetime timeout 120 秒で分割され、後半はデータ送信側が src の新フローになるはず
    packets.append(tcp_pkt(CLIENT, SERVER, 40030, 80, seq=8000, ack=0, flags="S",
                           win=WIN, time_=at(3)))
    packets.append(tcp_pkt(SERVER, CLIENT, 80, 40030, seq=9000, ack=8001, flags="SA",
                           win=WIN, time_=at(3, 10000), c2s=False))
    packets.append(tcp_pkt(CLIENT, SERVER, 40030, 80, seq=8001, ack=9001, flags="A",
                           win=WIN, time_=at(3, 20000)))
    packets.append(tcp_pkt(CLIENT, SERVER, 40030, 80, seq=8001, ack=9001, flags="PA",
                           payload=b"\x41" * 100, win=WIN, time_=at(3, 30000)))
    packets.append(tcp_pkt(CLIENT, SERVER, 40030, 80, seq=8101, ack=9001, flags="PA",
                           payload=b"\x41" * 100, win=WIN, time_=at(133)))

    write("08_duration.pcap", packets)
    print("08_duration.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
