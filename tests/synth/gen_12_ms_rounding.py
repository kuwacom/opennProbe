# SPDX-License-Identifier: GPL-3.0-or-later
"""12_ms_rounding.pcap: FLOW_DURATION_MILLISECONDS / START・END の us 端数丸め方向

- S17 (sport 44001, t=0): UDP 2 パケット t=0.000000 / 1.999500 -> DUR 1999(floor) or 2000(round)
- S18 (sport 44002, t=10): UDP 2 パケット t=10.000000 / 11.500000 -> DUR 1500(どちらでも同じ)
- S19 (sport 44003, t=20): UDP 2 パケット t=20.000000 / 20.999500 -> DUR 999(floor) or 1000(round)
- S20 (sport 44004, t=30): UDP 2 パケット t=30.000000 / 30.999999(端数 999us) -> 同上
"""
from typing import List

from scapy.packet import Packet

from helper import at, udp_pkt, write


def main() -> None:
    packets: List[Packet] = []
    # 30001: 128B, t=0 と 1.9995 秒
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44001, 9990, ip_len=128,
                           time_=at(0)))
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44001, 9990, ip_len=128,
                           time_=at(1, 999500)))
    # 30002: t=10 と 11.5 秒
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44002, 9990, ip_len=128,
                           time_=at(10)))
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44002, 9990, ip_len=128,
                           time_=at(11, 500000)))
    # 30003: t=20 と 20.9995 秒
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44003, 9990, ip_len=128,
                           time_=at(20)))
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44003, 9990, ip_len=128,
                           time_=at(20, 999500)))
    # 30004: t=30 と 30.999999 秒
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44004, 9990, ip_len=128,
                           time_=at(30)))
    packets.append(udp_pkt("198.18.13.1", "198.18.13.2", 44004, 9990, ip_len=128,
                           time_=at(30, 999999)))
    write("12_ms_rounding.pcap", packets)
    print("12_ms_rounding.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
