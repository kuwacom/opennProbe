"""06_icmp.pcap: echo request/reply と type/code 違いの ICMP フロー群

目的: ICMP_TYPE = 最初のパケットの type×256+code、ICMP_IPV4_TYPE = 最初のパケットの
type という規則を検証する。I4 は最初のパケット以降に別 type を混ぜて、
最初のパケットで決まることを確認する
"""
from typing import List

from scapy.packet import Packet

from helper import at, icmp_pkt, write

# echo のペイロード(ICMP 全体 19 バイト → IP 全長 39)
ECHO_PAYLOAD = b"nprobe-icmp"

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_ECHO = 8
ICMP_TIME_EXCEEDED = 11


def main() -> None:
    packets: List[Packet] = []

    # I1: echo request(type8/code0) -> echo reply(type0/code0)
    #     期待 ICMP_TYPE=8×256+0=2048 / ICMP_IPV4_TYPE=8
    packets.append(icmp_pkt("198.18.7.1", "198.18.7.2", ICMP_ECHO, 0, id_=1, seq=1,
                            payload=ECHO_PAYLOAD, time_=at(0)))
    packets.append(icmp_pkt("198.18.7.2", "198.18.7.1", ICMP_ECHO_REPLY, 0, id_=1, seq=1,
                            payload=ECHO_PAYLOAD, time_=at(0, 10000), c2s=False))

    # I2: destination unreachable(type3/code1)→ 期待 3×256+1=769 / 3
    packets.append(icmp_pkt("198.18.7.1", "198.18.7.3", ICMP_DEST_UNREACH, 1, time_=at(1)))

    # I3: time exceeded(type11/code0)→ 期待 11×256+0=2816 / 11
    packets.append(icmp_pkt("198.18.7.1", "198.18.7.4", ICMP_TIME_EXCEEDED, 0, time_=at(2)))

    # I4: request/reply/request/reply(最初のパケットが request)
    #     途中に type0 が混ざっても最初のパケット(type8)で決まるか
    packets.append(icmp_pkt("198.18.7.5", "198.18.7.1", ICMP_ECHO, 0, id_=2, seq=1,
                            payload=ECHO_PAYLOAD, time_=at(3)))
    packets.append(icmp_pkt("198.18.7.1", "198.18.7.5", ICMP_ECHO_REPLY, 0, id_=2, seq=1,
                            payload=ECHO_PAYLOAD, time_=at(3, 10000), c2s=False))
    packets.append(icmp_pkt("198.18.7.5", "198.18.7.1", ICMP_ECHO, 0, id_=2, seq=2,
                            payload=ECHO_PAYLOAD, time_=at(3, 20000)))
    packets.append(icmp_pkt("198.18.7.1", "198.18.7.5", ICMP_ECHO_REPLY, 0, id_=2, seq=2,
                            payload=ECHO_PAYLOAD, time_=at(3, 30000), c2s=False))

    # I5: destination unreachable(type3/code3)→ 期待 3×256+3=771 / 3
    packets.append(icmp_pkt("198.18.7.6", "198.18.7.1", ICMP_DEST_UNREACH, 3, time_=at(4)))

    write("06_icmp.pcap", packets)
    print("06_icmp.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
