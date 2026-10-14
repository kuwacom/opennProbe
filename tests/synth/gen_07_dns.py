"""07_dns.pcap: A/AAAA レコードのクエリと応答(TTL つき)

目的: DNS_QUERY_ID / DNS_QUERY_TYPE(最初の DNS メッセージの ID と最初の質問の type)、
DNS_TTL_ANSWER(最初の応答の質問部直後の最初の RR の TTL・回答/権威/追加どれでも)
を検証する
D5 は同一 5-tuple で別 ID の再問い合わせを置き、区切り規則(別 ID は無関係に新フロー)
も確認する
"""
from typing import List

from scapy.layers.dns import DNSRR, DNSRRSOA
from scapy.packet import Packet

from helper import at, dns_query, dns_response, write

CLIENT_IP = "198.18.8.1"
SERVER_IP = "198.18.8.2"


def main() -> None:
    packets: List[Packet] = []

    # D1: A レコード(id=0x1234)→ 回答部 A TTL=300
    #     期待 ID=4660 / QUERY_TYPE=1 / TTL_ANSWER=300
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50010, 0x1234, "one.example.com",
                             time_=at(0)))
    packets.append(dns_response(SERVER_IP, CLIENT_IP, 50010, 0x1234, "one.example.com",
                                answer=DNSRR(rrname="one.example.com", type="A", ttl=300,
                                             rdata="192.0.2.1"),
                                time_=at(0, 10000)))

    # D2: AAAA レコード(id=0x5678)→ 回答部 AAAA TTL=60
    #     期待 ID=22136 / QUERY_TYPE=28 / TTL_ANSWER=60
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50011, 0x5678, "two.example.com",
                             qtype="AAAA", time_=at(1)))
    packets.append(dns_response(SERVER_IP, CLIENT_IP, 50011, 0x5678, "two.example.com",
                                qtype="AAAA",
                                answer=DNSRR(rrname="two.example.com", type="AAAA", ttl=60,
                                             rdata="2001:db8::1"),
                                time_=at(1, 10000)))

    # D3: A レコード(id=0x9abc)→ 回答 0 件で権威部 SOA のみ(TTL=120)
    #     期待 TTL_ANSWER=120(質問部直後の最初の RR が権威部の SOA)
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50012, 0x9abc, "three.example.com",
                             time_=at(2)))
    packets.append(dns_response(SERVER_IP, CLIENT_IP, 50012, 0x9abc, "three.example.com",
                                authority=DNSRRSOA(rrname="three.example.com", type="SOA",
                                                   ttl=120,
                                                   mname="ns1.example.com",
                                                   rname="admin.example.com", serial=1,
                                                   refresh=7200, retry=900, expire=1209600,
                                                   minimum=60),
                                time_=at(2, 10000)))

    # D4: 応答なしのクエリ(id=0xdef0)→ 期待 TTL_ANSWER=0
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50013, 0xdef0, "four.example.com",
                             time_=at(3)))

    # D5: 同一 5-tuple で別 ID の再問い合わせ(id=0x1111 → 0x2222)
    #     期待: 別 ID のクエリで新フローに分かれる(区切り規則)
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50014, 0x1111, "five.example.com",
                             time_=at(4)))
    packets.append(dns_response(SERVER_IP, CLIENT_IP, 50014, 0x1111, "five.example.com",
                                answer=DNSRR(rrname="five.example.com", type="A", ttl=120,
                                             rdata="192.0.2.5"),
                                time_=at(4, 10000)))
    packets.append(dns_query(CLIENT_IP, SERVER_IP, 50014, 0x2222, "five.example.com",
                             time_=at(4, 20000)))
    packets.append(dns_response(SERVER_IP, CLIENT_IP, 50014, 0x2222, "five.example.com",
                                answer=DNSRR(rrname="five.example.com", type="A", ttl=120,
                                             rdata="192.0.2.5"),
                                time_=at(4, 30000)))

    write("07_dns.pcap", packets)
    print("07_dns.pcap: %d packets" % len(packets))


if __name__ == "__main__":
    main()
