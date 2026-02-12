#!/usr/bin/env python3
"""
Create deterministic, class-balanced JSONL eval subsets from a larger JSONL set.

We keep the JSON schema consistent with existing `data/subset60_*.jsonl`:
  {"id": "...", "text": "...", "label": 0|1, "category": "..."}

The meta file mirrors `data/subset60_meta.json` and stores 1-based source row
numbers into the *source* dataset for reproducibility.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class Row:
    rownum_1b: int
    text: str
    label: int


def _read_rows(path: Path) -> list[Row]:
    rows: list[Row] = []
    with path.open("r", encoding="utf-8") as f:
        for i0, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(
                Row(
                    rownum_1b=i0 + 1,
                    text=str(obj["text"]),
                    label=int(obj["label"]),
                )
            )
    return rows


def _sample_balanced(rows: list[Row], n: int, seed: int) -> list[Row]:
    if n <= 0:
        raise ValueError("--n must be > 0")
    if n % 2 != 0:
        raise ValueError("--n must be even to enforce class balance (n/2 benign + n/2 attack)")

    benign = [r for r in rows if r.label == 0]
    attack = [r for r in rows if r.label == 1]
    if len(benign) < n // 2 or len(attack) < n // 2:
        raise ValueError(
            f"insufficient class counts: benign={len(benign)} attack={len(attack)} need_each={n//2}"
        )

    rng = random.Random(seed)
    chosen = rng.sample(benign, n // 2) + rng.sample(attack, n // 2)
    rng.shuffle(chosen)
    return chosen


def _write_jsonl(path: Path, items: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False))
            f.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Source JSONL (must contain text + label fields).")
    ap.add_argument("--n", type=int, required=True, help="Number of prompts to sample (must be even).")
    ap.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed.")
    ap.add_argument("--id-prefix", default="s", help="Subset id prefix (e.g. s500).")
    ap.add_argument("--out-pi", required=True, help="Output JSONL for category=prompt_injection.")
    ap.add_argument("--out-jb", required=True, help="Output JSONL for category=jailbreak.")
    ap.add_argument("--out-meta", required=True, help="Output meta JSON.")
    args = ap.parse_args()

    src = Path(args.input)
    rows = _read_rows(src)
    chosen = _sample_balanced(rows, args.n, args.seed)

    width = max(3, len(str(args.n)))
    ids = [f"{args.id_prefix}_{i:0{width}d}" for i in range(1, args.n + 1)]

    pi_items = []
    jb_items = []
    source_rows_1b: list[int] = []
    benign = 0
    attack = 0
    for sid, row in zip(ids, chosen, strict=True):
        source_rows_1b.append(row.rownum_1b)
        if row.label == 0:
            benign += 1
        else:
            attack += 1
        pi_items.append({"id": sid, "text": row.text, "label": row.label, "category": "prompt_injection"})
        jb_items.append({"id": sid, "text": row.text, "label": row.label, "category": "jailbreak"})

    _write_jsonl(Path(args.out_pi), pi_items)
    _write_jsonl(Path(args.out_jb), jb_items)

    meta = {
        "seed": args.seed,
        "total": args.n,
        "benign": benign,
        # Historic naming: subset60_meta.json uses "jailbreak" to mean "attack" (label=1).
        "jailbreak": attack,
        "source": str(src),
        "source_rows": source_rows_1b,
    }
    out_meta = Path(args.out_meta)
    out_meta.parent.mkdir(parents=True, exist_ok=True)
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

