import os
import pandas as pd

INPUT = "./data/baseline-26060802"
OUTPUT = "./tmp/baseline3.csv"
SMOOTH_WINDOW = 40


def parse_number(s):
    # The data uses '.' as a thousands separator and ',' as the decimal mark.
    # 'packets/period' is an integer (e.g. "64.418" -> 64418); 'period/sec' is
    # a float (e.g. "0,010110" -> 0.010110).
    return s.replace(".", "").replace(",", ".")


def parse(path):
    blocks = []
    current = {}
    with open(path, "r") as f:
        for raw in f:
            line = raw.replace("\x1b[2J", "").replace("[2J", "").strip()
            if not line or line.startswith("XDP_action"):
                if current.get("period") is not None:
                    blocks.append(current)
                current = {}
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[0]
            pkts_per_period = int(parse_number(parts[2]))
            period_sec = float(parse_number(parts[3]))
            if name == "XDP_ABORTED":
                current["aborted_pkts"] = pkts_per_period
                current.setdefault("period", period_sec)
            elif name == "XDP_DROP":
                current["drop_pkts"] = pkts_per_period
                current["period"] = period_sec
            elif name == "XDP_PASS":
                current["pass_pkts"] = pkts_per_period
                current["period"] = period_sec
    if current.get("period") is not None:
        blocks.append(current)
    return blocks


def main():
    rows = parse(INPUT)
    df = pd.DataFrame(rows).fillna(0)
    df["time"] = df["period"].cumsum()
    # The 'packets/period' column is the rate already (pps computed over the
    # period); the 'period/sec' column is just the sampling interval used.
    # Emit in kpps so pgfplots stays within TeX dimension range.
    df["aborted"] = df["aborted_pkts"] / 1e3
    df["drop"] = df["drop_pkts"] / 1e3
    df["pass"] = df["pass_pkts"] / 1e3

    for col in ("aborted", "drop", "pass"):
        df[col] = df[col].rolling(SMOOTH_WINDOW, center=True, min_periods=1).mean()

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    df[["time", "aborted", "drop", "pass"]].to_csv(OUTPUT, index=False)


if __name__ == "__main__":
    main()
