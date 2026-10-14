# SPDX-License-Identifier: GPL-3.0-or-later
"""公式 NF-CSE-CIC-IDS2018-v3 フル CSV から日単位の行を抽出する(ストリーム処理)

フル CSV を一括読みせず 1 行ずつ読み捨てるので、メモリは一定量しか使わない
- 条件: FLOW_START_MILLISECONDS が [開始日 + day-start-hour, 開始日 + days + day-start-hour) の行
  - CSE-CIC-IDS2018 の「日」は現地日なので、日境界は UTC 04:00(既定)にずれている
  - 公式 CSV は FLOW_START_MILLISECONDS 昇順だが末尾に時刻の飛びがあるため、
    早抜け(範囲を越えたら終了)はせず最後まで走査する
- 出力: 先頭列に ROW(公式 CSV のデータ行番号・1 始まり)を付けた、元 CSV と同じ列順
  - ROW は調査・追跡用で、突き合わせでは使わない(--no-row で付けない)

使い方: official_extract.py <公式フルCSV> <出力CSV> --start-day 2018-02-14 [--days 1] [--day-start-hour 4]
"""

import argparse
import csv
import sys
from datetime import datetime, timedelta, timezone


def day_ms(day: str, hour: int) -> int:
    dt = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(hours=hour)
    return int(dt.timestamp() * 1000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--start-day", required=True, help="抽出する現地日(YYYY-MM-DD、UTC 基準)")
    ap.add_argument("--days", type=int, default=1, help="抽出する日数(既定 1)")
    ap.add_argument("--day-start-hour", type=int, default=4,
                    help="日の開始時刻(UTC 時。既定 4 = CSE-CIC-IDS2018 の現地日慣習)")
    ap.add_argument("--no-row", action="store_true", help="ROW 列を付けない")
    a = ap.parse_args()

    lo = day_ms(a.start_day, a.day_start_hour)
    hi = lo + a.days * 86_400_000
    n_data = n_out = n_bad = 0
    with open(a.src, newline="") as f, open(a.out, "w", newline="") as g:
        reader = csv.reader(f)
        writer = csv.writer(g)
        header = next(reader)
        if header[0] != "FLOW_START_MILLISECONDS":
            sys.exit(f"先頭列が FLOW_START_MILLISECONDS でない: {header[0]}")
        writer.writerow(["ROW"] + header if not a.no_row else header)
        for row in reader:
            n_data += 1
            try:
                st = int(row[0])
            except ValueError:
                # 数値でない開始時刻は既知の抽出対象に含まれていないため無視する(件数だけ数える)
                n_bad += 1
                continue
            if lo <= st < hi:
                writer.writerow([n_data] + row if not a.no_row else row)
                n_out += 1
    print(f"公式 {n_data} 行を走査し {n_out} 行を出力(数値でない開始時刻 {n_bad} 行)")


if __name__ == "__main__":
    main()
