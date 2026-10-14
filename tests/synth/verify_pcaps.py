# SPDX-License-Identifier: GPL-3.0-or-later
"""生成 pcap の読み戻し検証

各 pcap のパケット数・時刻範囲と、パケットごとの IP 全長 / TTL / 送受信 /
TCP seq・flags・window / ICMP type・code / DNS id・qr を出力する
生成した pcap の中身を目で確かめるための確認用

使い方: verify_pcaps.py [pcap のディレクトリ(既定: カレント)]
"""
import sys
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, rdpcap
from scapy.layers.dns import DNS
from scapy.packet import Packet


def describe(idx: int, p: Packet) -> str:
    """パケット 1 個を検証用の 1 行に整形する"""
    t = p.time
    sec = int(t)
    usec = int(round((t - sec) * 1000000))
    ip = p[IP]
    line = "#%02d t=%d.%06d len=%d ttl=%d %s" % (idx, sec, usec, ip.len, ip.ttl, ip.src)
    if TCP in p:
        tcp = p[TCP]
        line += ":%d > %s:%d TCP %s seq=%d ack=%d win=%d" % (
            tcp.sport, ip.dst, tcp.dport, str(tcp.flags), tcp.seq, tcp.ack, tcp.window)
    elif UDP in p:
        udp = p[UDP]
        line += ":%d > %s:%d UDP" % (udp.sport, ip.dst, udp.dport)
        if p.haslayer(DNS):
            d = p[DNS]
            line += " dns id=%d qr=%d" % (d.id, d.qr)
    elif ICMP in p:
        icmp = p[ICMP]
        line += " > %s ICMP type=%d code=%d" % (ip.dst, icmp.type, icmp.code)
    return line


def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    for pcap_path in sorted(base.glob("*.pcap")):
        pkts = rdpcap(str(pcap_path))
        print("== %s: %d pkts, %s .. %s" % (pcap_path.name, len(pkts), pkts[0].time, pkts[-1].time))
        for i, p in enumerate(pkts):
            print(describe(i, p))


if __name__ == "__main__":
    main()
