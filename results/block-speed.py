from pathlib import Path
import pandas as pd

START_MARK = "XDP_ABORTED"

def _read_trimmed_lines(path: Path) -> list[str]:
    lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    while lines and not lines[-1].startswith(START_MARK):
        lines.pop()
    if lines:
        lines.pop()  # drop the last START_MARK itself
    while lines and not lines[0].startswith(START_MARK):
        lines.pop(0)
    if not lines:
        raise ValueError(f"No data blocks found (missing {START_MARK}) in {path}")
    return lines

def _detect_block_size(lines: list[str]) -> int:
    if not lines or not lines[0].startswith(START_MARK):
        raise ValueError("Lines must start with START_MARK to detect block size.")
    for i in range(1, len(lines)):
        if lines[i].startswith(START_MARK):
            return i
    raise ValueError("Could not detect block size (only one START_MARK found).")

def _file_to_long_df(path: Path, drop_all_zero_blocks: bool = True) -> pd.DataFrame:
    """
    Returns long DF with columns:
      block | Action | total_packets | packets | time diff
    """
    lines = _read_trimmed_lines(path)
    block_size = _detect_block_size(lines)

    rows = []
    block_idx = -1

    for i in range(0, len(lines) - (len(lines) % block_size), block_size):
        block = lines[i:i + block_size]

        parsed = []
        for ln in block:
            parts = ln.split()
            if len(parts) < 4:
                continue
            action = parts[0]
            total_packets = int(parts[1].replace(".", ""))
            packets = int(parts[2].replace(".", ""))
            time_diff = float(parts[3].replace(",", "."))
            parsed.append((action, total_packets, packets, time_diff))

        if not parsed:
            continue

        if drop_all_zero_blocks and all(tp < 10 for _, tp, _, _ in parsed):
            # Skip entirely idle blocks (prevents large time offsets at start if early blocks are idle)
            continue

        block_idx += 1
        for action, total_packets, packets, time_diff in parsed:
            rows.append((block_idx, action, total_packets, packets, time_diff))

    if not rows:
        raise ValueError(f"No usable rows parsed from {path}")

    df = pd.DataFrame(rows, columns=["block", "Action", "total_packets", "packets", "time diff"])
    return df

def build_and_save_per_action_time(
    file_dict: dict[str, str],
    window: int = 10,
    min_periods: int = 1,
    out_sep: str = ";",
    normalize_time: bool = False,
    drop_all_zero_blocks: bool = True,
    format: str = "long",  # "long" (tidy) or "wide"
) -> dict[str, pd.DataFrame]:
    """
    One CSV per key. Per-action cumulative time is computed:
        time_action = groupby(Action)['time diff'].cumsum()
    Rolling mean is applied to 'packets' per action.

    format="long": columns [block, action, time, value] (+ raw if you need)
    format="wide": columns [block, time__<act>..., <act>...] (one time column per action)
    """
    out = {}

    for key, file_path in file_dict.items():
        path = Path(file_path)
        df_long = _file_to_long_df(path, drop_all_zero_blocks=drop_all_zero_blocks)

        # per-action cumulative time
        df_long["time_action"] = df_long.groupby("Action")["time diff"].cumsum()
        if normalize_time:
            df_long["time_action"] = df_long["time_action"] - df_long.groupby("Action")["time_action"].transform("first")

        # rolling mean per action (on packets)
        df_long["value"] = (
            df_long.sort_values(["Action", "block"])
                  .groupby("Action")["packets"]
                  .transform(lambda s: s.rolling(window=window, min_periods=min_periods).mean())
                  # .transform(lambda s: s.groupby((s.index // 10)).transform("mean"))
        )
        df_long["value"] = df_long["value"]/(3000000+42000)

        if format == "long":
            # tidy output: one row per (block, action)
            combined = (
                df_long[["block", "Action", "time_action", "value"]]
                .rename(columns={"Action": "action", "time_action": "time"})
                .sort_values(["block", "action"])
                .reset_index(drop=True)
            )
        elif format == "wide":
            # wide with separate time columns per action
            wide_values = (
                df_long.pivot_table(index="block", columns="Action", values="value", aggfunc="first")
                       .sort_index()
            )
            wide_times = (
                df_long.pivot_table(index="block", columns="Action", values="time_action", aggfunc="first")
                       .sort_index()
            )
            # prefix time columns so both can co-exist
            wide_times.columns = [f"time__{c}" for c in wide_times.columns]
            combined = pd.concat([wide_times, wide_values], axis=1).reset_index()
            time_cols = combined.filter(like="time__")               # all cols starting with "time__"
            combined = combined[ time_cols.lt(20).all(axis=1) ]      # keep only rows where *all* < 20
        else:
            raise ValueError("format must be 'long' or 'wide'")

        # save
        safe_suffix = str(path).replace("/", "_")
        out_name = f"./tmp/{key}_{safe_suffix}.csv"
        combined.to_csv(out_name, sep=out_sep, index=False)
        out[key] = combined

    return out

def parse_answere_rates(path: str, save_csv_path: str, out_sep: str = ";") -> pd.DataFrame:

    df = pd.read_csv(path, sep=",", names=["time", "value", "cumulative"],header=1)
    
    df['seconds'] = df['time'] #+1.96 # pd.to_timedelta("00:"+df['time']).dt.total_seconds()
    df.loc[-1] = [0,0,0,0]  # adding a row
    df.index = df.index + 1  # shifting index
    df.sort_index(inplace=True)

    sub = df[df['seconds'] < 20]
    pd.DataFrame({
        "time":      sub['seconds'],
        "responses": sub['value'] / 4200
    }).fillna(0).to_csv(f"./tmp/{save_csv_path}", sep=out_sep, index=False)
    # df['value_ma10'] = df['value'].rolling(window=10).mean()*10
    #pd.DataFrame({ "time": df['seconds'], "responses":df['value_ma10']}).fillna(0).to_csv(f"./tmp/{save_csv_path}", sep=out_sep, index=False)
    return df

data = build_and_save_per_action_time(
    {
        "file": "./data/fips3/6a40186daa3c49f2b8797e310bb7cc1d",
        "fips": "./data/fips3/8ed40ac68e71469581c555b622865819",
    },
    window=10,
    min_periods=1,
    normalize_time=False,       # make each action’s time start at 0.0
    drop_all_zero_blocks=True,# keep idle periods in the time accumulation
    format="wide",             # or "wide"
)

print(parse_answere_rates("./data/fips2/6a40186daa3c49f2b8797e310bb7cc1d-result.txt", "file-response.csv"))
parse_answere_rates("./data/fips2/8ed40ac68e71469581c555b622865819-result.txt", "fips-response.csv")
df_file = data["file"]
df_fips = data["fips"]
