#!/usr/bin/env python3
"""packet_sanitizer.py - Clean packet dataset CSVs to mitigate poisoning."""
from pathlib import Path
import pandas as pd
import sys


def sanitize_csv(in_path: Path, out_path: Path) -> None:
    df = pd.read_csv(in_path)
    df = df.dropna()
    numeric = df.select_dtypes(include=['number']).columns
    if 'ttl' in numeric:
        df = df[(df['ttl'] >= 0) & (df['ttl'] <= 255)]
    if 'dport' in numeric:
        df = df[(df['dport'] >= 0) & (df['dport'] <= 65535)]
    if 'len' in numeric:
        df = df[(df['len'] > 0) & (df['len'] < 65535)]
    df.to_csv(out_path, index=False)


def main() -> None:
    if len(sys.argv) != 3:
        print('Usage: packet_sanitizer.py <input_csv> <output_csv>')
        sys.exit(1)
    sanitize_csv(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == '__main__':
    main()
