# SPDX-License-Identifier: GPL-3.0-or-later
"""合成 pcap 生成の共通ヘルパ(nProbe 10.4 の挙動の観測に使ったものと同じ構成)

- pcap 時刻は BASE_SEC(整数エポック秒)+秒/us オフセットを EDecimal で構築する
  float を time に直接入れると us 変換で丸め誤差が出るため、nProbe の ms 切り捨て検証に支障する
- IP 全長はペイロード長で制御し、scapy の自動計算に任せる(固定値の上書きはしない)
- アドレスは 198.18.0.0/15(RFC 2544 のベンチマーク用)。観測時の 10.0.0.0/16 から第 1・2 オクテットだけ置き換えた
"""
import os
from pathlib import Path
from typing import Iterable, List, Optional

from scapy.all import ICMP, IP, Raw, TCP, UDP, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRSOA
from scapy.packet import Packet
from scapy.utils import EDecimal

# 共通の時刻基準(エポック秒)。検証の再現性のため固定値
BASE_SEC = 1760000000

# クライアント側 / サーバ側のダミー MAC(nProbe は MAC を向き判定に使わないが、
# パケットの発信側が分かるように Ethernet ヘッダは物理的な向きに合わせる)
MAC_C = "02:00:00:00:00:01"
MAC_S = "02:00:00:00:00:02"


def at(sec: int = 0, usec: int = 0) -> EDecimal:
    """pcap 時刻(BASE_SEC + sec + usec)を正確な EDecimal で返す

    @param sec - BASE_SEC からのオフセット秒
    @param usec - 追加のマイクロ秒
    @returns エポック秒(EDecimal)
    """
    return EDecimal(BASE_SEC + sec) + EDecimal(usec) / EDecimal(1000000)


def out_dir() -> Path:
    """出力先(環境変数 SYNTH_OUT。未指定ならカレントディレクトリ)"""
    return Path(os.environ.get("SYNTH_OUT", "."))


def write(filename: str, packets: Iterable[Packet]) -> Path:
    """Ethernet pcap として出力先(out_dir)に書き出す

    @param filename - 出力ファイル名
    @param packets - Ethernet ヘッダ済みのパケット列
    @returns 出力ファイルのパス
    """
    path = out_dir() / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def _finish(pkt: Packet, time_: Optional[EDecimal]) -> Packet:
    """pcap 時刻を設定して返す"""
    if time_ is not None:
        pkt.time = time_
    return pkt


def _eth(c2s: bool, inner: Packet) -> Packet:
    """Ethernet ヘッダを付ける(発信側に合わせて MAC を付け替える)"""
    if c2s:
        return Ether(src=MAC_C, dst=MAC_S) / inner
    return Ether(src=MAC_S, dst=MAC_C) / inner


def udp_pkt(src: str, dst: str, sport: int, dport: int, ip_len: Optional[int] = None,
            ttl: int = 64, time_: Optional[EDecimal] = None, c2s: bool = True) -> Packet:
    """UDP パケットを構築する

    @param ip_len - 目標 IP total length(None ならペイロードなし)。ペイロード長 = ip_len - 28 で調整する
    @param c2s - クライアント -> サーバのパケットなら True(MAC の向きだけに使う)
    """
    payload_len = ip_len - 28 if ip_len is not None else 0
    inner = (IP(src=src, dst=dst, ttl=ttl) / UDP(sport=sport, dport=dport) /
             Raw(load=b"\x00" * payload_len))
    return _finish(_eth(c2s, inner), time_)


def tcp_pkt(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: str,
            win: int = 8192, payload: bytes = b"", ttl: int = 64,
            options: Optional[list] = None, time_: Optional[EDecimal] = None,
            c2s: bool = True) -> Packet:
    """TCP パケットを構築する

    @param options - TCP オプション([("WScale", 7)] 等)
    @param c2s - クライアント -> サーバのパケットなら True(MAC の向きだけに使う)
    """
    inner = (IP(src=src, dst=dst, ttl=ttl) /
             TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=win,
                 options=options or []) /
             Raw(load=payload))
    return _finish(_eth(c2s, inner), time_)


def icmp_pkt(src: str, dst: str, type_: int, code: int, id_: int = 1, seq: int = 1,
             payload: bytes = b"", ttl: int = 64, time_: Optional[EDecimal] = None,
             c2s: bool = True) -> Packet:
    """ICMP パケットを構築する

    @param c2s - クライアント -> サーバのパケットなら True(MAC の向きだけに使う)
    """
    inner = (IP(src=src, dst=dst, ttl=ttl) / ICMP(type=type_, code=code, id=id_, seq=seq) /
             Raw(load=payload))
    return _finish(_eth(c2s, inner), time_)


def dns_query(client_ip: str, server_ip: str, client_port: int, txid: int, qname: str,
              qtype: str = "A", time_: Optional[EDecimal] = None) -> Packet:
    """DNS クエリ(client -> server)を構築する"""
    inner = (IP(src=client_ip, dst=server_ip) / UDP(sport=client_port, dport=53) /
             DNS(id=txid, qr=0, qd=DNSQR(qname=qname, qtype=qtype)))
    return _finish(_eth(True, inner), time_)


def dns_response(server_ip: str, client_ip: str, client_port: int, txid: int, qname: str,
                 qtype: str = "A", answer: Optional[Packet] = None,
                 authority: Optional[Packet] = None,
                 time_: Optional[EDecimal] = None) -> Packet:
    """DNS 応答(server -> client)を構築する(answer=回答部の RR / authority=権威部の RR)"""
    fields: dict = {"id": txid, "qr": 1, "qd": DNSQR(qname=qname, qtype=qtype)}
    if answer is not None:
        fields["an"] = answer
    if authority is not None:
        fields["ns"] = authority
    inner = (IP(src=server_ip, dst=client_ip) / UDP(sport=53, dport=client_port) /
             DNS(**fields))
    return _finish(_eth(False, inner), time_)
