# SPDX-License-Identifier: GPL-3.0-or-later
"""opennprobe(C++ 実装の pcap -> NF-v3 CSV 変換)を Python から呼ぶ薄いラッパー

実行ファイルの場所は引数 binary・環境変数 OPENNPROBE_BIN・PATH 上の opennprobe・
リポジトリ内の build/opennprobe の順に探す
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

__all__ = ["OpennprobeError", "convert", "convert_many", "find_binary"]

_REPO_BUILD = Path(__file__).resolve().parents[2] / "build" / "opennprobe"


class OpennprobeError(RuntimeError):
    """変換の失敗(終了コードと標準エラーを持つ)"""

    def __init__(self, returncode: int, stderr: str) -> None:
        super().__init__(f"opennprobe が終了コード {returncode} で失敗しました: {stderr.strip()}")
        self.returncode = returncode
        self.stderr = stderr


def find_binary(binary: str | os.PathLike[str] | None = None) -> str:
    """opennprobe の実行ファイルのパスを返す"""
    if binary is not None:
        return os.fspath(binary)
    env = os.environ.get("OPENNPROBE_BIN")
    if env:
        return env
    found = shutil.which("opennprobe")
    if found:
        return found
    if _REPO_BUILD.is_file():
        return str(_REPO_BUILD)
    raise FileNotFoundError("opennprobe が見つかりません(OPENNPROBE_BIN を設定してください)")


def _common_args(l7: bool, compat: str, extra_args: Sequence[str]) -> list[str]:
    args = ["--compat", compat]
    if not l7:
        args.append("--no-l7")
    args.extend(extra_args)
    return args


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise OpennprobeError(proc.returncode, proc.stderr)
    return proc


def convert(
    pcap: str | os.PathLike[str],
    out: str | os.PathLike[str],
    *,
    l7: bool = True,
    compat: str = "official",
    extra_args: Sequence[str] = (),
    binary: str | os.PathLike[str] | None = None,
) -> Path:
    """pcap 1 本を CSV に変換し、出力パスを返す"""
    cmd = [find_binary(binary), *_common_args(l7, compat, extra_args), "-o", os.fspath(out), os.fspath(pcap)]
    _run(cmd)
    return Path(out)


def convert_many(
    pcaps: Iterable[str | os.PathLike[str]],
    out_dir: str | os.PathLike[str],
    *,
    jobs: int | None = None,
    l7: bool = True,
    compat: str = "official",
    extra_args: Sequence[str] = (),
    binary: str | os.PathLike[str] | None = None,
) -> list[Path]:
    """複数の pcap をファイル単位で並列に変換し、<out_dir>/<pcap 名>.csv のリストを返す

    並列化は opennprobe の -j(ファイルごとに別プロセス)に任せる
    """
    paths = [os.fspath(p) for p in pcaps]
    if not paths:
        return []
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    n = jobs if jobs is not None else (os.cpu_count() or 1)
    if len(paths) == 1:
        return [convert(paths[0], out / (Path(paths[0]).name + ".csv"), l7=l7, compat=compat,
                        extra_args=extra_args, binary=binary)]
    cmd = [find_binary(binary), *_common_args(l7, compat, extra_args), "-j", str(n), "-o", str(out), *paths]
    _run(cmd)
    return [out / (Path(p).name + ".csv") for p in paths]
